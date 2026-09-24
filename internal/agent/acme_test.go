package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
)

func TestACMEValidate(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		cfg     ACMEConfig
		dir     string
		wantSub string // empty means it must be accepted
	}{
		{"disabled is always fine", ACMEConfig{}, "", ""},
		{"accepted and valid", ACMEConfig{Domain: "files.example.com", AcceptTOS: true}, dir, ""},
		{"server hostname needs no domain", ACMEConfig{UseServerHostname: true, AcceptTOS: true}, dir, ""},
		{"a certificate needs a directory to front", ACMEConfig{Domain: "a.example.com", AcceptTOS: true}, "", "pass --dir"},
		{"the subscriber agreement is not assumed", ACMEConfig{Domain: "a.example.com"}, dir, "--acme-accept-tos"},
		{"a URL is not a hostname", ACMEConfig{Domain: "https://a.example.com", AcceptTOS: true}, dir, "not a URL"},
		{"host:port is not a hostname", ACMEConfig{Domain: "a.example.com:443", AcceptTOS: true}, dir, "not a URL"},
		{"a wildcard needs DNS-01", ACMEConfig{Domain: "*.example.com", AcceptTOS: true}, dir, "wildcard"},
		{"a bare label is not issuable", ACMEConfig{Domain: "localhost", AcceptTOS: true}, dir, "no dot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate(tt.dir)
			if tt.wantSub == "" {
				if err != nil {
					t.Fatalf("validate rejected a valid config: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate accepted %+v, want an error mentioning %q", tt.cfg, tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantSub)
			}
		})
	}
}

// Accepting a certificate authority's subscriber agreement is a decision that
// belongs to a person, so it has no default and the refusal has to name the
// flag that grants it.
func TestACMERefusesWithoutTOSAcceptance(t *testing.T) {
	_, err := New(Config{
		Server:   "h:1",
		Token:    "t",
		ServeDir: t.TempDir(),
		ACME:     ACMEConfig{Domain: "files.example.com"},
	})
	if err == nil {
		t.Fatal("New accepted a certificate request with no agreement acceptance")
	}
	if !strings.Contains(err.Error(), "--acme-accept-tos") {
		t.Errorf("error = %v, want it to name --acme-accept-tos", err)
	}
}

// Issuance needs 80 and 443 reachable, so they are published whether or not the
// operator listed them. A request against a port the server never bound fails
// looking like a CA problem rather than a configuration one.
func TestACMEPublishesItsChallengePorts(t *testing.T) {
	ag, err := New(Config{
		Server:   "h:1",
		Token:    "t",
		ServeDir: t.TempDir(),
		ACME:     ACMEConfig{Domain: "files.example.com", AcceptTOS: true},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, spec := range ACMEPorts {
		if !ag.allowed[spec] {
			t.Errorf("port %s was not published", spec)
		}
	}
	// --dir-port is not published when a certificate moves the directory to
	// 80/443; publishing it too would expose the files over plain HTTP on a
	// third port, which is the opposite of what asking for TLS meant.
	if ag.allowed[portspec.Spec{Port: 8080, Proto: portspec.TCP}] {
		t.Error("the plain --dir-port was published alongside the TLS ports")
	}
}

func TestResolveHostname(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ACMEConfig
		lease   string
		want    string
		wantErr string
	}{
		{"an explicit domain wins", ACMEConfig{Domain: "a.example.com"}, "b.example.com", "a.example.com", ""},
		{"the server names us", ACMEConfig{UseServerHostname: true}, "b.example.com", "b.example.com", ""},
		{"asked the server and it had no zone", ACMEConfig{UseServerHostname: true}, "", "", "no --zone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.resolveHostname(tt.lease)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveHostname: %v", err)
			}
			if got != tt.want {
				t.Errorf("hostname = %q, want %q", got, tt.want)
			}
		})
	}
}

// The cache holds the ACME account key, which is a credential, so the directory
// it lives in must not be world-readable.
func TestACMECacheDirIsPrivate(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "acme")
	cfg := ACMEConfig{Domain: "files.example.com", AcceptTOS: true, CacheDir: cache}
	if _, err := cfg.manager("files.example.com"); err != nil {
		t.Fatalf("manager: %v", err)
	}
	info, err := os.Stat(cache)
	if err != nil {
		t.Fatalf("the cache directory was not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("cache directory mode = %#o, want 0700", perm)
	}
}
