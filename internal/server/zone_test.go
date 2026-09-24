package server

import (
	"strings"
	"testing"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/pool"
)

func TestValidateZone(t *testing.T) {
	tests := []struct {
		name    string
		zone    string
		wantSub string // empty means it must be accepted
	}{
		{"an ordinary zone", "tunnel.example.com", ""},
		{"a two-label zone", "example.com", ""},
		{"a URL is not a zone", "https://tunnel.example.com", "not a URL"},
		{"host:port is not a zone", "tunnel.example.com:443", "not a URL"},
		{"a leading dot", ".example.com", "dot"},
		{"a trailing dot", "example.com.", "dot"},
		{"a bare label", "internal", "no dot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateZone(tt.zone)
			if tt.wantSub == "" {
				if err != nil {
					t.Fatalf("validateZone rejected %q: %v", tt.zone, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateZone accepted %q, want an error mentioning %q", tt.zone, tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantSub)
			}
		})
	}
}

// Agent ids come from an operator-written tokens file and are not constrained
// to DNS syntax, so they have to be coerced into something a CA will issue for
// rather than producing a request rejected for reasons that never mention the
// tokens file.
func TestDNSLabel(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"laptop", "laptop"},
		{"Laptop", "laptop"},
		{"build-box-2", "build-box-2"},
		{"M's laptop", "m-s-laptop"},
		{"M's  laptop", "m-s-laptop"},
		{"--edges--", "edges"},
		{"...", ""},
		{"", ""},
		{strings.Repeat("a", 80), strings.Repeat("a", 63)},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := dnsLabel(tt.in)
			if got != tt.want {
				t.Errorf("dnsLabel(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if len(got) > maxLabelLen {
				t.Errorf("dnsLabel(%q) is %d bytes, over the %d-byte DNS limit", tt.in, len(got), maxLabelLen)
			}
			if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") {
				t.Errorf("dnsLabel(%q) = %q, which is not a valid label", tt.in, got)
			}
		})
	}
}

func TestHostnameFor(t *testing.T) {
	withZone := &Server{zone: "tunnel.example.com"}
	noZone := &Server{}

	if got := withZone.hostnameFor("laptop", true); got != "laptop.tunnel.example.com" {
		t.Errorf("hostname = %q, want laptop.tunnel.example.com", got)
	}
	// An agent that did not ask gets nothing, and a server with no zone has
	// nothing to give. Both must be empty rather than a partial name, because
	// the lease's omitempty makes absent and empty the same answer.
	if got := withZone.hostnameFor("laptop", false); got != "" {
		t.Errorf("hostname for an agent that did not ask = %q, want empty", got)
	}
	if got := noZone.hostnameFor("laptop", true); got != "" {
		t.Errorf("hostname with no zone configured = %q, want empty", got)
	}
	// An id that coerces to nothing must not produce ".tunnel.example.com".
	if got := withZone.hostnameFor("...", true); got != "" {
		t.Errorf("hostname for an unusable id = %q, want empty", got)
	}
}

// A hostname is only useful with a DNS record behind it, and a random pool
// moves the address that record points at on every reconnect. Startup is the
// only place this can be caught: by the time a certificate fails, the cause
// looks like a CA problem.
func TestZoneRefusesRandomAllocation(t *testing.T) {
	randomPool, err := pool.New([]string{"192.0.2.0/30"}, pool.Random)
	if err != nil {
		t.Fatalf("pool.New: %v", err)
	}
	_, err = New(Config{
		Pool: randomPool,
		Auth: StaticTokens{"t": "agent"},
		Zone: "tunnel.example.com",
	})
	if err == nil {
		t.Fatal("New accepted --zone with random allocation")
	}
	if !strings.Contains(err.Error(), "incompatible") {
		t.Errorf("error = %v, want it to say the two are incompatible", err)
	}

	// The same zone against a sticky pool is fine, which is what makes the
	// refusal above about the combination rather than about the zone.
	stickyPool, err := pool.New([]string{"192.0.2.0/30"}, pool.Sticky)
	if err != nil {
		t.Fatalf("pool.New: %v", err)
	}
	if _, err := New(Config{
		Pool: stickyPool,
		Auth: StaticTokens{"t": "agent"},
		Zone: "tunnel.example.com",
	}); err != nil {
		t.Errorf("New rejected --zone with sticky allocation: %v", err)
	}
}
