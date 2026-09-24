package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
)

// ACMEPorts are the ports a certificate needs published.
//
// 443 carries the served directory over TLS; 80 carries the HTTP-01 challenge
// and redirects everything else. Both are added to the declaration
// automatically, because a certificate request against a port the server never
// bound fails in a way that looks like a CA problem rather than a
// configuration one.
var ACMEPorts = []portspec.Spec{
	{Port: 80, Proto: portspec.TCP},
	{Port: 443, Proto: portspec.TCP},
}

// LetsEncryptDirectory is the default ACME endpoint.
const LetsEncryptDirectory = acme.LetsEncryptURL

// LetsEncryptStagingDirectory issues untrusted certificates against far looser
// rate limits. Named here because the production endpoint's limits are low
// enough that a debugging loop will hit them, and the remedy is otherwise a
// URL you have to go and find.
const LetsEncryptStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// ACMEConfig describes how the agent obtains a certificate for its served
// directory.
type ACMEConfig struct {
	// Domain is the hostname to obtain a certificate for. Leave empty and set
	// UseServerHostname to take whatever name the server assigns.
	Domain string
	// UseServerHostname asks the server for a name from its zone.
	UseServerHostname bool
	// AcceptTOS records that the operator accepted the CA's subscriber
	// agreement. There is no default: accepting an agreement on someone's
	// behalf is not a decision this program gets to make, so it is refused
	// rather than assumed.
	AcceptTOS bool
	// DirectoryURL is the ACME endpoint. Empty means Let's Encrypt production.
	DirectoryURL string
	// CacheDir stores issued certificates and the account key. Empty picks a
	// per-user cache directory. Persisting it matters: without it every restart
	// is a fresh issuance, which is how an agent walks into a rate limit.
	CacheDir string
	// Email is an optional contact the CA uses for expiry warnings.
	Email string
}

// enabled reports whether a certificate was asked for at all.
func (c ACMEConfig) enabled() bool { return c.Domain != "" || c.UseServerHostname }

// validate checks the configuration before anything connects, so a refusal
// arrives as a usage error rather than as a failed issuance ten seconds later.
func (c ACMEConfig) validate(serveDir string) error {
	if !c.enabled() {
		return nil
	}
	if serveDir == "" {
		return errors.New("agent: a certificate only fronts a served directory; pass --dir")
	}
	if !c.AcceptTOS {
		return errors.New("agent: obtaining a certificate requires accepting the CA's subscriber agreement; pass --acme-accept-tos")
	}
	if c.Domain != "" {
		if err := validateDomain(c.Domain); err != nil {
			return err
		}
	}
	return nil
}

// validateDomain rejects names a CA will not issue for, before the request is
// made. The checks are deliberately shallow — a hostname's real validity is the
// CA's call — but they catch the mistakes that produce an opaque ACME error.
func validateDomain(domain string) error {
	switch {
	case strings.Contains(domain, "/") || strings.Contains(domain, ":"):
		return fmt.Errorf("agent: --domain %q should be a hostname, not a URL or host:port", domain)
	case strings.HasPrefix(domain, "*."):
		return fmt.Errorf("agent: --domain %q is a wildcard, which needs the DNS-01 challenge this agent does not implement", domain)
	case !strings.Contains(domain, "."):
		return fmt.Errorf("agent: --domain %q has no dot; a public CA will not issue for a bare label", domain)
	}
	return nil
}

// defaultCacheDir picks a per-user directory for the certificate cache.
func defaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("agent: no cache directory available, pass --acme-cache: %w", err)
	}
	return filepath.Join(base, "v46-tunnel", "acme"), nil
}

// manager builds the autocert manager for a resolved hostname.
//
// The hostname is resolved late — it may have come from the server's lease — so
// this is called after the handshake rather than at construction.
func (c ACMEConfig) manager(hostname string) (*autocert.Manager, error) {
	if err := validateDomain(hostname); err != nil {
		return nil, err
	}
	cacheDir := c.CacheDir
	if cacheDir == "" {
		var err error
		if cacheDir, err = defaultCacheDir(); err != nil {
			return nil, err
		}
	}
	// 0700: the cache holds the ACME account key, which is a credential.
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: creating the certificate cache: %w", err)
	}

	m := &autocert.Manager{
		Cache:  autocert.DirCache(cacheDir),
		Prompt: autocert.AcceptTOS,
		// A whitelist of exactly one name. Without a host policy autocert would
		// request a certificate for any name in an incoming SNI, which on a
		// public address is a request anyone passing by can trigger.
		HostPolicy: autocert.HostWhitelist(hostname),
		Email:      c.Email,
	}
	if c.DirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: c.DirectoryURL}
	}
	return m, nil
}

// resolveHostname decides which name to request a certificate for, given what
// the server said in the lease.
func (c ACMEConfig) resolveHostname(leaseHostname string) (string, error) {
	if c.Domain != "" {
		return c.Domain, nil
	}
	if leaseHostname == "" {
		return "", errors.New("agent: asked the server for a hostname but the lease carried none; the server has no --zone configured")
	}
	return leaseHostname, nil
}
