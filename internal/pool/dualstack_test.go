package pool

import (
	"errors"
	"net/netip"
	"testing"
)

// familiesOf reports which families a lease covers.
func familiesOf(addrs []netip.Addr) map[Family]netip.Addr {
	out := make(map[Family]netip.Addr, len(addrs))
	for _, a := range addrs {
		out[familyOf(a)] = a
	}
	return out
}

// A pool holding both families leases one address of each, which is what lets a
// single hostname carry both an A and an AAAA record. Leasing one address could
// not express that at all.
func TestDualStackPoolLeasesOneOfEachFamily(t *testing.T) {
	p := mustNew(t, "192.0.2.0/30", "2001:db8::/126")

	addrs, err := p.Acquire("laptop")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	byFamily := familiesOf(addrs)
	if len(addrs) != 2 {
		t.Fatalf("leased %v, want one IPv4 and one IPv6 address", addrs)
	}
	if _, ok := byFamily[IPv4]; !ok {
		t.Errorf("lease %v has no IPv4 address", addrs)
	}
	if _, ok := byFamily[IPv6]; !ok {
		t.Errorf("lease %v has no IPv6 address", addrs)
	}
}

// A single-family pool must keep leasing exactly one address. The dual-stack
// change must not turn every existing deployment into one that hands out two.
func TestSingleFamilyPoolLeasesOneAddress(t *testing.T) {
	for _, entry := range []string{"192.0.2.0/30", "2001:db8::/126"} {
		t.Run(entry, func(t *testing.T) {
			p := mustNew(t, entry)
			addrs, err := p.Acquire("laptop")
			if err != nil {
				t.Fatalf("Acquire: %v", err)
			}
			if len(addrs) != 1 {
				t.Errorf("leased %v from a single-family pool, want one address", addrs)
			}
		})
	}
}

func TestFamiliesReportsWhatThePoolHolds(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    int
	}{
		{"IPv4 only", []string{"192.0.2.0/30"}, 1},
		{"IPv6 only", []string{"2001:db8::/126"}, 1},
		{"both", []string{"192.0.2.0/30", "2001:db8::/126"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustNew(t, tt.entries...)
			if got := len(p.Families()); got != tt.want {
				t.Errorf("Families() = %v, want %d families", p.Families(), tt.want)
			}
		})
	}
}

// Running out of one family must not deny the other. Refusing a working IPv6
// lease because the IPv4 half is exhausted would take the whole agent offline
// over a shortage that only affects half its addresses.
func TestExhaustingOneFamilyStillLeasesTheOther(t *testing.T) {
	// One IPv4 address, four IPv6.
	p := mustNew(t, "192.0.2.7", "2001:db8::/126")

	first, err := p.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire(alice): %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("alice leased %v, want a dual-stack lease", first)
	}

	// IPv4 is now gone, but IPv6 is not.
	second, err := p.Acquire("bob")
	if err != nil {
		t.Fatalf("Acquire(bob) failed although IPv6 was free: %v", err)
	}
	byFamily := familiesOf(second)
	if _, ok := byFamily[IPv4]; ok {
		t.Errorf("bob got an IPv4 address from an exhausted family: %v", second)
	}
	if _, ok := byFamily[IPv6]; !ok {
		t.Fatalf("bob leased %v, want an IPv6 address", second)
	}
}

// Only when EVERY family is exhausted is the pool exhausted.
func TestExhaustedWhenNoFamilyHasAnything(t *testing.T) {
	p := mustNew(t, "192.0.2.7", "2001:db8::1")

	if _, err := p.Acquire("alice"); err != nil {
		t.Fatalf("Acquire(alice): %v", err)
	}
	if _, err := p.Acquire("bob"); !errors.Is(err, ErrExhausted) {
		t.Errorf("Acquire on a fully exhausted pool = %v, want ErrExhausted", err)
	}
}

// Stickiness is per family: a reconnecting agent must get BOTH of its previous
// addresses back, not just whichever the allocator happened to reach first.
func TestDualStackStickyKeepsBothAddresses(t *testing.T) {
	p := mustNew(t, "192.0.2.0/29", "2001:db8::/125")

	// Hold something ahead of laptop in each family, then free it, so a plain
	// first-free allocator would hand laptop different addresses on reconnect.
	if _, err := p.Acquire("alice"); err != nil {
		t.Fatalf("Acquire(alice): %v", err)
	}
	first, err := p.Acquire("laptop")
	if err != nil {
		t.Fatalf("Acquire(laptop): %v", err)
	}
	p.Release("alice")
	p.Release("laptop")

	again, err := p.Acquire("laptop")
	if err != nil {
		t.Fatalf("re-Acquire: %v", err)
	}
	beforeByFamily, afterByFamily := familiesOf(first), familiesOf(again)
	if len(afterByFamily) != len(beforeByFamily) {
		t.Fatalf("reconnect leased %v, want the same families as %v", again, first)
	}
	for fam, want := range beforeByFamily {
		if got := afterByFamily[fam]; got != want {
			t.Errorf("%s address after reconnect = %v, want %v", fam, got, want)
		}
	}
}

// Releasing must free every address the agent held, not only the first.
func TestReleaseFreesBothFamilies(t *testing.T) {
	p := mustNew(t, "192.0.2.7", "2001:db8::1")

	addrs, err := p.Acquire("laptop")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if p.Free() != 0 {
		t.Fatalf("Free = %d after a dual-stack lease of a two-address pool, want 0", p.Free())
	}
	p.Release("laptop")
	if p.Free() != 2 {
		t.Errorf("Free = %d after release, want 2; an address was leaked", p.Free())
	}
	for _, a := range addrs {
		if holder, ok := p.Holder(a); ok {
			t.Errorf("released address %v still held by %q", a, holder)
		}
	}
}

// A double acquire must return the same SET, or a flapping dual-stack agent
// consumes two addresses per reconnect instead of one.
func TestDualStackDoubleAcquireIsIdempotent(t *testing.T) {
	p := mustNew(t, "192.0.2.0/30", "2001:db8::/126")

	first, err := p.Acquire("flappy")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	second, err := p.Acquire("flappy")
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if len(second) != len(first) {
		t.Fatalf("second Acquire returned %v, want %v", second, first)
	}
	for i := range first {
		if second[i] != first[i] {
			t.Errorf("second Acquire returned %v, want the held set %v", second, first)
			break
		}
	}
	// 2 IPv4 usable in a /30 plus 4 IPv6 in a /126 = 6 total, 2 leased.
	if p.Free() != 4 {
		t.Errorf("Free = %d, want 4; the pool leaked addresses to a double acquire", p.Free())
	}
}

// An IPv4-mapped IPv6 address is reachable as IPv4, so it must count as the
// IPv4 family rather than silently becoming a second IPv6 lease.
func TestIPv4MappedCountsAsIPv4(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	if got := familyOf(mapped); got != IPv4 {
		t.Errorf("familyOf(%v) = %v, want ipv4", mapped, got)
	}
}
