package subdomain

import (
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// A label has to be a legal DNS label, or every name built from it fails at the
// resolver rather than here.
var labelRE = regexp.MustCompile(`^[a-z0-9]+$`)

func TestNewLabelShape(t *testing.T) {
	label, err := NewLabel()
	if err != nil {
		t.Fatalf("NewLabel: %v", err)
	}
	if len(label) != Length {
		t.Errorf("label %q is %d characters, want %d", label, len(label), Length)
	}
	if !labelRE.MatchString(label) {
		t.Errorf("label %q is not a legal DNS label", label)
	}
	// base32 without padding: an "=" would be rejected by a resolver and is the
	// mistake a padded encoding makes silently.
	if strings.Contains(label, "=") {
		t.Errorf("label %q carries base32 padding", label)
	}
}

// Labels must not repeat. A collision would hand one agent's traffic to
// another, so this checks the generator actually draws on randomness rather
// than, say, a counter or a fixed seed.
func TestNewLabelIsUnique(t *testing.T) {
	const draws = 2000
	seen := make(map[string]struct{}, draws)
	for range draws {
		label, err := NewLabel()
		if err != nil {
			t.Fatalf("NewLabel: %v", err)
		}
		if _, dup := seen[label]; dup {
			t.Fatalf("label %q was minted twice in %d draws", label, draws)
		}
		seen[label] = struct{}{}
	}
}

func addrs(t *testing.T, in ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, len(in))
	for i, a := range in {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func TestBindAndLookup(t *testing.T) {
	r := NewRegistry("tun.example.com")
	b, err := r.Bind("laptop", addrs(t, "198.51.100.7", "2001:db8::7"))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if b.FQDN(r.Zone()) != b.Label+".tun.example.com" {
		t.Errorf("FQDN = %q", b.FQDN(r.Zone()))
	}

	got, ok := r.Lookup(b.Label)
	if !ok {
		t.Fatal("the bound label does not resolve")
	}
	if len(got) != 2 {
		t.Errorf("resolved to %v, want both addresses", got)
	}
}

// A reconnect gets a fresh label, and the old one must stop resolving in the
// same breath — otherwise a dead name keeps pointing at an address that may
// already belong to a different agent.
func TestRebindReleasesThePreviousLabel(t *testing.T) {
	r := NewRegistry("tun.example.com")

	first, err := r.Bind("laptop", addrs(t, "198.51.100.7"))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	second, err := r.Bind("laptop", addrs(t, "198.51.100.8"))
	if err != nil {
		t.Fatalf("re-Bind: %v", err)
	}
	if second.Label == first.Label {
		t.Fatal("a reconnect reused its label; the answer said fresh random every session")
	}
	if _, ok := r.Lookup(first.Label); ok {
		t.Error("the previous label still resolves after a rebind")
	}
	if _, ok := r.Lookup(second.Label); !ok {
		t.Error("the new label does not resolve")
	}
	if r.Len() != 1 {
		t.Errorf("registry holds %d labels after a rebind, want 1", r.Len())
	}
}

func TestReleaseRemovesTheLabel(t *testing.T) {
	r := NewRegistry("tun.example.com")
	b, err := r.Bind("laptop", addrs(t, "198.51.100.7"))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	r.Release("laptop")
	if _, ok := r.Lookup(b.Label); ok {
		t.Error("the label still resolves after release")
	}
	if r.Len() != 0 {
		t.Errorf("registry holds %d labels after release, want 0", r.Len())
	}
	// Releasing an agent that holds nothing must not panic or remove someone
	// else's binding.
	r.Release("never-connected")
}

// The registry hands out copies. A caller mutating what it got back must not be
// able to change what the nameserver answers.
func TestLookupReturnsACopy(t *testing.T) {
	r := NewRegistry("tun.example.com")
	b, err := r.Bind("laptop", addrs(t, "198.51.100.7"))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got, _ := r.Lookup(b.Label)
	got[0] = netip.MustParseAddr("203.0.113.1")

	again, _ := r.Lookup(b.Label)
	if again[0].String() != "198.51.100.7" {
		t.Errorf("mutating a Lookup result changed the registry: %v", again[0])
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"Tun.Example.COM.": "tun.example.com",
		"tun.example.com":  "tun.example.com",
		"ABC.":             "abc",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// A stale challenge answered beside a fresh one fails validation for no visible
// reason, so publishing replaces rather than appends.
func TestSetTXTReplaces(t *testing.T) {
	r := NewRegistry("tun.example.com")
	name := "_acme-challenge.tun.example.com"

	r.SetTXT(name, "first")
	r.SetTXT(name, "second")
	got, ok := r.TXT(name)
	if !ok {
		t.Fatal("no TXT published")
	}
	if len(got) != 1 || got[0] != "second" {
		t.Errorf("TXT = %v, want only the latest value", got)
	}
}

func TestConcurrentBindAndLookup(t *testing.T) {
	r := NewRegistry("tun.example.com")
	const agents = 64

	var wg sync.WaitGroup
	labels := make([]string, agents)
	for i := range agents {
		wg.Go(func() {
			b, err := r.Bind(agentName(i), addrs(t, "198.51.100.7"))
			if err != nil {
				t.Errorf("Bind: %v", err)
				return
			}
			labels[i] = b.Label
		})
	}
	wg.Wait()

	if r.Len() != agents {
		t.Errorf("registry holds %d labels, want %d", r.Len(), agents)
	}
	for i, label := range labels {
		if label == "" {
			continue
		}
		if _, ok := r.Lookup(label); !ok {
			t.Errorf("label for agent %d does not resolve", i)
		}
	}
}

func agentName(i int) string {
	return "agent-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
}
