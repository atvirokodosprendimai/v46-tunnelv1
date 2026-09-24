// Package tlsutil loads the certificates both ends of the tunnel authenticate
// with, and can mint a throwaway one for local development.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// ServerConfig loads a server certificate and key from disk.
func ServerConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: loading server certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, nil
}

// SelfSigned mints a short-lived certificate for the given hosts.
//
// It exists so a developer can run the two binaries against each other without
// a CA. It is not a production path: the agent has to be told to trust it, and
// the fingerprint is printed so that trust can at least be pinned rather than
// disabled outright.
func SelfSigned(hosts []string) (*tls.Config, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "v46-tunnel development"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", err
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		MinVersion:   tls.VersionTLS13,
	}
	return conf, Fingerprint(leaf), nil
}

// Fingerprint renders a certificate's SHA-256 fingerprint in the colon-separated
// hex form an operator can compare by eye.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	hexed := hex.EncodeToString(sum[:])
	var b strings.Builder
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexed[i : i+2])
	}
	return b.String()
}

// ClientConfig builds the agent's TLS settings.
//
// pin, when set, is a SHA-256 fingerprint as printed by Fingerprint: the
// certificate chain is then checked against it instead of against the system
// roots, which is what makes a self-signed development server usable without
// turning verification off. insecure disables verification entirely and is
// refused unless the caller really asked for it, because a tunnel is exactly
// the kind of thing worth impersonating.
func ClientConfig(serverName, pin string, insecure bool) (*tls.Config, error) {
	conf := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS13}
	switch {
	case pin != "" && insecure:
		return nil, errors.New("tlsutil: a certificate pin and --insecure are contradictory; choose one")
	case pin != "":
		want := normalizeFingerprint(pin)
		// The pin replaces chain verification rather than adding to it: a
		// development certificate has no chain to a system root, so verifying
		// both would refuse exactly the case the pin exists for.
		conf.InsecureSkipVerify = true
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					continue
				}
				if normalizeFingerprint(Fingerprint(cert)) == want {
					return nil
				}
			}
			return errors.New("tlsutil: server certificate does not match the pinned fingerprint")
		}
	case insecure:
		conf.InsecureSkipVerify = true
	}
	return conf, nil
}

// normalizeFingerprint makes fingerprint comparison insensitive to the
// separators and casing different tools print.
func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(s))
}

// LoadTokens reads an authenticator from a file of "<token> <agent-name>" lines.
// Blank lines and lines beginning with # are ignored. A line with no name uses
// the token itself as the identity, which still gives the agent a stable sticky
// address.
func LoadTokens(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: reading tokens: %w", err)
	}
	tokens := make(map[string]string)
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		token, name, _ := strings.Cut(line, " ")
		name = strings.TrimSpace(name)
		if name == "" {
			name = token
		}
		if _, dup := tokens[token]; dup {
			return nil, fmt.Errorf("tlsutil: %s line %d: duplicate token", path, n+1)
		}
		tokens[token] = name
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("tlsutil: %s defines no tokens", path)
	}
	return tokens, nil
}
