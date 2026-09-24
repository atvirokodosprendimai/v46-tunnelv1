package pool

import (
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"testing"
)

// Random mode is the opposite of the sticky guarantee, and the test has to be
// able to tell them apart. A single acquire/release cycle cannot: a random pick
// can legitimately return the same address twice in a row. Over many cycles
// against a large pool it effectively never returns the same one every time, so
// "more than one distinct address was seen" separates random from sticky with a
// false-failure probability around 256^-19.
func TestRandomModeDoesNotKeepReturningOneAddress(t *testing.T) {
	p := mustNewMode(t, Random, "10.0.0.0/24")

	seen := make(map[netip.Addr]struct{})
	for range 20 {
		seen[acquireOne(t, p, "laptop")] = struct{}{}
		p.Release("laptop")
	}
	if len(seen) == 1 {
		t.Error("Random mode returned the same address on all 20 reconnects; that is the sticky behaviour")
	}
}

// The same sequence under Sticky must return exactly one address. Without this
// half, the test above could pass on a pool broken in some other way, and
// nothing would pin that the default still behaves as the default.
func TestStickyModeKeepsReturningOneAddress(t *testing.T) {
	p := mustNewMode(t, Sticky, "10.0.0.0/24")

	seen := make(map[netip.Addr]struct{})
	for range 20 {
		seen[acquireOne(t, p, "laptop")] = struct{}{}
		p.Release("laptop")
	}
	if len(seen) != 1 {
		t.Errorf("Sticky mode returned %d distinct addresses across reconnects, want 1", len(seen))
	}
}

// Random mode remembers nothing, but it must still not hand one agent two
// addresses when a reconnect races its own dead session's cleanup — otherwise a
// flapping agent drains the pool.
func TestRandomModeDoubleAcquireIsIdempotent(t *testing.T) {
	p := mustNewMode(t, Random, "192.0.2.1", "192.0.2.2", "192.0.2.3")

	first := acquireOne(t, p, "flappy")
	second := acquireOne(t, p, "flappy")
	if second != first {
		t.Errorf("second Acquire returned %v, want the held address %v", second, first)
	}
	if p.Free() != 2 {
		t.Errorf("Free = %d, want 2; the pool leaked an address to a double acquire", p.Free())
	}
}

// Random mode must exhaust cleanly rather than looping or handing out an
// address someone already holds: the sampling walks only free addresses, and an
// empty reservoir is the exhausted case.
func TestRandomModeExhausts(t *testing.T) {
	p := mustNewMode(t, Random, "192.0.2.1", "192.0.2.2")

	held := make(map[netip.Addr]string)
	for _, agent := range []string{"a", "b"} {
		addr := acquireOne(t, p, agent)
		if prev, dup := held[addr]; dup {
			t.Fatalf("address %v leased to both %s and %s", addr, prev, agent)
		}
		held[addr] = agent
	}
	if _, err := p.Acquire("c"); !errors.Is(err, ErrExhausted) {
		t.Errorf("Acquire on an exhausted random pool = %v, want ErrExhausted", err)
	}
}

// Random mode must not double-lease under concurrency either. The sticky path
// has its own version of this test; the picking code differs between the two,
// so one does not cover the other.
func TestRandomModeConcurrentAcquireNeverDoubleLeases(t *testing.T) {
	const agents = 64
	p := mustNewMode(t, Random, "10.0.0.0/24")

	got := make([]netip.Addr, agents)
	var wg sync.WaitGroup
	for i := range agents {
		wg.Go(func() {
			addrs, err := p.Acquire(agentName(i))
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			got[i] = addrs[0]
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

// agentName gives each concurrent acquirer a distinct identity, since two
// acquires under one name are deliberately idempotent.
func agentName(i int) string { return "agent-" + strconv.Itoa(i) }

// Mode.String feeds the server's startup log, which is how an operator confirms
// --random-ip actually took effect.
func TestModeString(t *testing.T) {
	if got := Sticky.String(); got != "sticky" {
		t.Errorf("Sticky.String() = %q, want %q", got, "sticky")
	}
	if got := Random.String(); got != "random" {
		t.Errorf("Random.String() = %q, want %q", got, "random")
	}
}
