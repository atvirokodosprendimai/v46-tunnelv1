// Package wildcard obtains and renews the server's wildcard certificate.
//
// The certificate covers "*.<domain>", which is what lets any agent's random
// subdomain be served over TLS without a per-agent issuance. Only the DNS-01
// challenge can produce a wildcard at all, and this server is authoritative for
// its own zone — so it answers its own challenge by publishing the TXT record
// into the registry the nameserver reads.
//
// autocert is not used here: it implements HTTP-01 and TLS-ALPN-01 only, and
// neither can issue a wildcard. The order flow is driven directly against
// golang.org/x/crypto/acme instead.
package wildcard

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/subdomain"
)

// LetsEncryptStagingDirectory issues untrusted certificates against far looser
// rate limits. Named here because a wildcard order that fails on delegation is
// easy to retry into a production rate limit.
const LetsEncryptStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// renewBefore is how long before expiry a renewal is attempted. Let's Encrypt
// issues for 90 days and recommends renewing at 30 remaining, which leaves a
// month of failed attempts before anything breaks.
const renewBefore = 30 * 24 * time.Hour

// checkInterval is how often the certificate's remaining life is examined.
const checkInterval = 12 * time.Hour

// propagationWait is how long to wait after publishing the challenge TXT before
// telling the CA to look.
//
// The record is served by this process, so there is no propagation in the usual
// sense — but a CA may query through a resolver that already has the NXDOMAIN
// cached, and the zone's negative TTL is what bounds that.
const propagationWait = 20 * time.Second

// Config configures a Manager.
type Config struct {
	// Domain is the zone; the certificate covers "*.<Domain>" and the apex.
	Domain string
	// Registry publishes the challenge TXT records the nameserver serves.
	Registry *subdomain.Registry
	// CacheDir stores the certificate, its key, and the ACME account key.
	CacheDir string
	// DirectoryURL is the ACME endpoint. Empty means Let's Encrypt production.
	DirectoryURL string
	// Email is an optional contact for expiry warnings.
	Email string
	// AcceptTOS records that the operator accepted the CA's agreement.
	AcceptTOS bool
	// Logger receives structured events.
	Logger *slog.Logger
}

// Manager keeps a wildcard certificate current and serves it to TLS handshakes.
type Manager struct {
	domain   string
	registry *subdomain.Registry
	cacheDir string
	client   *acme.Client
	email    string
	log      *slog.Logger

	mu   sync.RWMutex
	cert *tls.Certificate
}

// New builds a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.Domain == "" {
		return nil, errors.New("wildcard: no domain")
	}
	if cfg.Registry == nil {
		return nil, errors.New("wildcard: no registry to publish challenges into")
	}
	if !cfg.AcceptTOS {
		return nil, errors.New("wildcard: obtaining a certificate requires accepting the CA's subscriber agreement; pass --acme-accept-tos")
	}
	if cfg.CacheDir == "" {
		return nil, errors.New("wildcard: no cache directory")
	}
	// 0700: the directory holds both the certificate key and the ACME account
	// key, either of which is enough to impersonate this zone.
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("wildcard: creating the cache directory: %w", err)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	accountKey, err := loadOrCreateKey(filepath.Join(cfg.CacheDir, "account.key"))
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: accountKey}
	if cfg.DirectoryURL != "" {
		client.DirectoryURL = cfg.DirectoryURL
	}

	m := &Manager{
		domain:   cfg.Domain,
		registry: cfg.Registry,
		cacheDir: cfg.CacheDir,
		client:   client,
		email:    cfg.Email,
		log:      log,
	}
	// A cached certificate means a restart serves TLS immediately instead of
	// waiting on an issuance, which is also what keeps a restart loop from
	// walking into a rate limit.
	if cert, err := m.loadCached(); err == nil {
		m.mu.Lock()
		m.cert = cert
		m.mu.Unlock()
		log.Info("loaded a cached wildcard certificate", "domain", m.names()[0], "expires", expiry(cert))
	}
	return m, nil
}

// names are the identifiers the certificate covers.
//
// The apex is included alongside the wildcard because "*.example.com" does NOT
// match "example.com" — a certificate for the wildcard alone fails on the zone
// itself, which is the one name an operator is most likely to try first.
func (m *Manager) names() []string {
	return []string{"*." + m.domain, m.domain}
}

// GetCertificate serves the wildcard to a TLS handshake. It is the
// tls.Config.GetCertificate hook.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("wildcard: no certificate yet")
	}
	return m.cert, nil
}

// Ready reports whether a certificate is available to serve.
func (m *Manager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert != nil
}

// Run obtains a certificate if there is none, then renews it before expiry,
// until ctx is done.
func (m *Manager) Run(ctx context.Context) error {
	if err := m.ensure(ctx); err != nil {
		// A failed first issuance is not fatal to the server: the tunnel still
		// carries every other port. It is retried on the next tick rather than
		// taking the process down.
		m.log.Error("could not obtain the wildcard certificate; TLS termination is unavailable until this succeeds", "err", err)
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := m.ensure(ctx); err != nil {
				m.log.Error("wildcard certificate renewal failed", "err", err)
			}
		}
	}
}

// ensure obtains a certificate when there is none or it is near expiry.
func (m *Manager) ensure(ctx context.Context) error {
	m.mu.RLock()
	cert := m.cert
	m.mu.RUnlock()

	if cert != nil && time.Until(expiry(cert)) > renewBefore {
		return nil
	}

	fresh, err := m.obtain(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.cert = fresh
	m.mu.Unlock()
	m.log.Info("wildcard certificate in place", "names", m.names(), "expires", expiry(fresh))
	return nil
}

// obtain runs one ACME order to completion.
func (m *Manager) obtain(ctx context.Context) (*tls.Certificate, error) {
	if _, err := m.client.Register(ctx, &acme.Account{Contact: contacts(m.email)}, acme.AcceptTOS); err != nil {
		// An account that already exists is the normal case on every run after
		// the first, and is not an error.
		if !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return nil, fmt.Errorf("wildcard: registering with the CA: %w", err)
		}
	}

	order, err := m.client.AuthorizeOrder(ctx, acme.DomainIDs(m.names()...))
	if err != nil {
		return nil, fmt.Errorf("wildcard: opening the order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := m.solve(ctx, authzURL); err != nil {
			return nil, err
		}
	}

	order, err = m.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("wildcard: waiting for the order: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: m.names(),
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("wildcard: building the CSR: %w", err)
	}

	der, _, err := m.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("wildcard: finalizing the order: %w", err)
	}

	cert, err := toCertificate(der, certKey)
	if err != nil {
		return nil, err
	}
	if err := m.store(der, certKey); err != nil {
		// Storing is best effort: a certificate in memory still serves. Saying
		// so matters because the consequence is a fresh issuance on restart,
		// which is how a restart loop hits a rate limit.
		m.log.Error("could not cache the wildcard certificate; a restart will re-issue", "err", err)
	}
	return cert, nil
}

// solve answers one authorization with a DNS-01 challenge.
func (m *Manager) solve(ctx context.Context, authzURL string) error {
	authz, err := m.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("wildcard: fetching the authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}

	var challenge *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			challenge = c
			break
		}
	}
	if challenge == nil {
		return errors.New("wildcard: the CA offered no dns-01 challenge, which is the only kind that can issue a wildcard")
	}

	value, err := m.client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return fmt.Errorf("wildcard: computing the challenge record: %w", err)
	}

	// The record name is the same for the wildcard and the apex — both
	// authorizations answer at _acme-challenge.<domain> — so the registry holds
	// whichever was published last. That is why the order's authorizations are
	// solved one at a time rather than in parallel.
	name := "_acme-challenge." + subdomain.Normalize(authz.Identifier.Value)
	m.registry.SetTXT(name, value)
	defer m.registry.ClearTXT(name)

	m.log.Info("published a dns-01 challenge", "name", name)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(propagationWait):
	}

	if _, err := m.client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("wildcard: accepting the challenge: %w", err)
	}
	if _, err := m.client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("wildcard: the CA could not validate %s (is the zone delegated to this host?): %w", name, err)
	}
	return nil
}

// contacts renders the ACME contact list.
func contacts(email string) []string {
	if email == "" {
		return nil
	}
	return []string{"mailto:" + email}
}

// expiry reports when a certificate stops being valid.
func expiry(cert *tls.Certificate) time.Time {
	if cert == nil || cert.Leaf == nil {
		return time.Time{}
	}
	return cert.Leaf.NotAfter
}

// toCertificate assembles a tls.Certificate with its leaf parsed, so expiry can
// be read without re-parsing on every check.
func toCertificate(der [][]byte, key crypto.PrivateKey) (*tls.Certificate, error) {
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, fmt.Errorf("wildcard: parsing the issued certificate: %w", err)
	}
	return &tls.Certificate{Certificate: der, PrivateKey: key, Leaf: leaf}, nil
}

// certPath and keyPath name the cached files.
func (m *Manager) certPath() string { return filepath.Join(m.cacheDir, "wildcard.crt") }
func (m *Manager) keyPath() string  { return filepath.Join(m.cacheDir, "wildcard.key") }

// store writes the issued certificate to the cache.
func (m *Manager) store(der [][]byte, key *ecdsa.PrivateKey) error {
	var certPEM []byte
	for _, block := range der {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block})...)
	}
	if err := os.WriteFile(m.certPath(), certPEM, 0o600); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(m.keyPath(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}

// loadCached reads a previously issued certificate.
func (m *Manager) loadCached() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(m.certPath(), m.keyPath())
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	return &cert, nil
}

// loadOrCreateKey reads the ACME account key, creating it on first run.
//
// The account key must persist: a new key is a new account, which loses the
// rate-limit standing and the issuance history of the old one.
func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("wildcard: %s is not a PEM key", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("wildcard: reading the account key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, fmt.Errorf("wildcard: writing the account key: %w", err)
	}
	return key, nil
}
