package pool

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func mustNew(t *testing.T, entries ...string) *Pool {
	t.Helper()
	p, err := New(entries)
	if err != nil {
		t.Fatalf("New(%v): %v", entries, err)
	}
	return p
}

func TestNewExpandsPrefixesAndAddresses(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    []string
	}{
		{"bare addresses keep order", []string{"10.0.0.5", "10.0.0.1"}, []string{"10.0.0.5", "10.0.0.1"}},
		{"a /30 skips network and broadcast", []string{"192.0.2.0/30"}, []string{"192.0.2.1", "192.0.2.2"}},
		{"a /31 is a point-to-point pair, both usable", []string{"192.0.2.0/31"}, []string{"192.0.2.0", "192.0.2.1"}},
		{"a /32 is the address itself", []string{"192.0.2.7/32"}, []string{"192.0.2.7"}},
		{"IPv6 has no broadcast address to skip", []string{"2001:db8::/126"}, []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}},
		{"duplicates across entries collapse", []string{"192.0.2.1", "192.0.2.0/30"}, []string{"192.0.2.1", "192.0.2.2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustNew(t, tt.entries...)
			var got []string
			for _, a := range p.all {
				got = append(got, a.String())
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("addresses = %v, want %v", got, tt.want)
			}
		})
	}
}

// A routed block's network and broadcast addresses are ordinary addresses, and
// listing one literally is how an operator says so.
func TestLiteralAddressBypassesEndSkipping(t *testing.T) {
	p := mustNew(t, "192.0.2.0")
	if p.Size() != 1 || p.all[0].String() != "192.0.2.0" {
		t.Errorf("literal network address was not kept: %v", p.all)
	}
}

func TestNewRejects(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		wantSub string
	}{
		{"nothing configured", nil, "no addresses configured"},
		{"not an address or prefix", []string{"not-an-ip"}, "neither an address nor a CIDR"},
		{"a prefix wide enough to be a typo", []string{"10.0.0.0/8"}, "expands past"},
		{"a /31 pair minus nothing is still fine, but a /32 network is not empty", []string{"192.0.2.0/33"}, "neither an address nor a CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.entries)
			if err == nil {
				t.Fatalf("New(%v) succeeded, want an error", tt.entries)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantSub)
			}
		})
	}
}

func TestAcquireAndRelease(t *testing.T) {
	p := mustNew(t, "192.0.2.1", "192.0.2.2")

	a, err := p.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire(alice): %v", err)
	}
	b, err := p.Acquire("bob")
	if err != nil {
		t.Fatalf("Acquire(bob): %v", err)
	}
	if a == b {
		t.Fatalf("two agents were leased the same address %v", a)
	}
	if p.Free() != 0 {
		t.Errorf("Free = %d, want 0", p.Free())
	}
	if _, err := p.Acquire("carol"); !errors.Is(err, ErrExhausted) {
		t.Errorf("Acquire on an exhausted pool = %v, want ErrExhausted", err)
	}

	p.Release("alice")
	if p.Free() != 1 {
		t.Errorf("Free after release = %d, want 1", p.Free())
	}
	if holder, ok := p.Holder(a); ok {
		t.Errorf("released address %v still held by %q", a, holder)
	}
}

// The sticky lease is the whole reason this package tracks identity: anything
// pointed at a published address caches it, so a reconnect that changes the
// address breaks callers that are doing nothing wrong.
//
// The arrangement matters: laptop is given the SECOND address and the first is
// then freed, so a plain first-free allocator would hand it .1. Only a real
// lookup of what laptop held before returns .2.
func TestReconnectKeepsItsAddress(t *testing.T) {
	p := mustNew(t, "192.0.2.1", "192.0.2.2", "192.0.2.3")

	if _, err := p.Acquire("alice"); err != nil {
		t.Fatalf("Acquire(alice): %v", err)
	}
	first, err := p.Acquire("laptop")
	if err != nil {
		t.Fatalf("Acquire(laptop): %v", err)
	}
	if first.String() != "192.0.2.2" {
		t.Fatalf("laptop was leased %v; this test needs it to hold the second address", first)
	}
	p.Release("alice")
	p.Release("laptop")

	again, err := p.Acquire("laptop")
	if err != nil {
		t.Fatalf("re-Acquire: %v", err)
	}
	if again != first {
		t.Errorf("reconnect got %v, want its previous address %v", again, first)
	}
}

// When the remembered address has been taken by someone else, the agent must
// still get a lease — a stale preference is a preference, not a reservation.
func TestStickyPreferenceYieldsWhenTaken(t *testing.T) {
	p := mustNew(t, "192.0.2.1", "192.0.2.2")

	first, err := p.Acquire("laptop")
	if err != nil {
		t.Fatalf("Acquire(laptop): %v", err)
	}
	p.Release("laptop")

	// alice takes the first free address, which is the one laptop just gave up.
	stolen, err := p.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire(alice): %v", err)
	}
	if stolen != first {
		t.Fatalf("alice was leased %v, want laptop's old address %v", stolen, first)
	}

	again, err := p.Acquire("laptop")
	if err != nil {
		t.Fatalf("Acquire when the preferred address is taken: %v", err)
	}
	if again == first {
		t.Errorf("laptop was leased %v, which alice is holding", again)
	}
	if holder, _ := p.Holder(first); holder != "alice" {
		t.Errorf("holder of %v = %q, want alice", first, holder)
	}
}

// A reconnect racing its own dead session's cleanup acquires twice. If that
// handed out two addresses, a flapping agent would drain the pool.
func TestDoubleAcquireIsIdempotent(t *testing.T) {
	p := mustNew(t, "192.0.2.1", "192.0.2.2", "192.0.2.3")
	first, err := p.Acquire("flappy")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	second, err := p.Acquire("flappy")
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if second != first {
		t.Errorf("second Acquire returned %v, want the held address %v", second, first)
	}
	if p.Free() != 2 {
		t.Errorf("Free = %d, want 2; the pool leaked an address to a double acquire", p.Free())
	}
}

func TestConcurrentAcquireNeverDoubleLeases(t *testing.T) {
	const agents = 64
	p := mustNew(t, "10.0.0.0/24")

	var wg sync.WaitGroup
	got := make([]netip.Addr, agents)
	for i := range agents {
		wg.Go(func() {
			a, err := p.Acquire(string(rune('a'+i%26)) + string(rune('0'+i/26)))
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			got[i] = a
		})
	}
	wg.Wait()

	seen := make(map[netip.Addr]int)
	for i, a := range got {
		if !a.IsValid() {
			continue
		}
		if prev, dup := seen[a]; dup {
			t.Fatalf("address %v leased to both agent %d and agent %d", a, prev, i)
		}
		seen[a] = i
	}
	if len(seen) != agents {
		t.Errorf("leased %d distinct addresses, want %d", len(seen), agents)
	}
}
