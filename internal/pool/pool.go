// Package pool hands out the addresses agents are published on.
//
// The addresses are assumed to already exist on the host — put on an interface
// by the operator, or routed to it as a block. The pool only tracks which are
// free, which keeps the server out of privileged netlink work and means a crash
// leaves no half-configured interface behind.
package pool

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
)

// MaxAddresses bounds how many addresses one pool may hold. A mistyped prefix
// is the realistic way to exceed it — "10.0.0.0/8" is sixteen million
// addresses, and materialising them would exhaust memory long before anyone
// noticed the typo.
const MaxAddresses = 65536

// ErrExhausted reports that every address in the pool is leased.
var ErrExhausted = errors.New("pool: no free addresses")

// Mode says how a free address is chosen for an agent.
type Mode int

const (
	// Sticky gives a reconnecting agent the address it held last, while that
	// address is still free.
	//
	// This is the default because everything pointed at a published address
	// caches it — DNS records, firewall rules, a client's config file — so an
	// address that changes on every reconnect quietly breaks callers that are
	// doing nothing wrong.
	Sticky Mode = iota

	// Random chooses uniformly among the free addresses and remembers nothing,
	// so a reconnecting agent generally lands somewhere new.
	//
	// It is the right choice when rotation is the point — cycling an address's
	// reputation, or keeping an agent's address from being a stable identifier
	// — and the wrong one for anything long-lived, for the reason Sticky names.
	Random
)

// String names the mode for logs.
func (m Mode) String() string {
	if m == Random {
		return "random"
	}
	return "sticky"
}

// Pool is a set of addresses and the leases held on them. It is safe for
// concurrent use.
type Pool struct {
	mu   sync.Mutex
	mode Mode
	// all preserves configuration order, so Sticky allocation is predictable
	// and an operator reading the logs sees addresses handed out in the order
	// they wrote them.
	all []netip.Addr
	// holder maps a leased address to the agent holding it.
	holder map[netip.Addr]string
	// held maps an agent to the address it currently holds. It is what makes a
	// repeated Acquire idempotent in both modes, and Release a lookup rather
	// than a scan.
	held map[string]netip.Addr
	// sticky remembers the last address each agent held, including after the
	// lease is released. It is the memory that makes a reconnect keep its
	// address, and it is deliberately never pruned, because an agent that
	// disconnects overnight is exactly the case it exists for. Unused in
	// Random mode, which is the whole of what Random means.
	sticky map[string]netip.Addr
}

// New builds a pool from a list of addresses and CIDR prefixes, in the order
// given. A bare address is taken literally; a prefix is expanded.
func New(entries []string, mode Mode) (*Pool, error) {
	p := &Pool{
		mode:   mode,
		holder: make(map[netip.Addr]string),
		held:   make(map[string]netip.Addr),
		sticky: make(map[string]netip.Addr),
	}
	seen := make(map[netip.Addr]struct{})
	for _, entry := range entries {
		addrs, err := expand(entry)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			p.all = append(p.all, a)
			if len(p.all) > MaxAddresses {
				return nil, fmt.Errorf("pool: more than %d addresses; a prefix this wide is usually a typo", MaxAddresses)
			}
		}
	}
	if len(p.all) == 0 {
		return nil, errors.New("pool: no addresses configured")
	}
	return p, nil
}

// Mode reports how this pool allocates.
func (p *Pool) Mode() Mode { return p.mode }

// Size reports how many addresses the pool holds.
func (p *Pool) Size() int { return len(p.all) }

// Free reports how many addresses are currently unleased.
func (p *Pool) Free() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.all) - len(p.holder)
}

// Acquire leases an address to agentID.
//
// An agent that acquires twice without releasing — a reconnect racing its own
// dead session's cleanup — gets the same address back rather than a second one,
// in either mode, so a flapping agent cannot drain the pool.
func (p *Pool) Acquire(agentID string) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if current, ok := p.held[agentID]; ok {
		return current, nil
	}
	if p.mode == Sticky {
		if want, ok := p.sticky[agentID]; ok {
			if _, leased := p.holder[want]; !leased {
				p.take(want, agentID)
				return want, nil
			}
		}
	}

	addr, ok := p.pickFree()
	if !ok {
		return netip.Addr{}, ErrExhausted
	}
	p.take(addr, agentID)
	return addr, nil
}

// pickFree chooses an unleased address according to the pool's mode. The caller
// holds the lock.
func (p *Pool) pickFree() (netip.Addr, bool) {
	if p.mode == Random {
		// Reservoir sampling over the free addresses: one pass, no allocation,
		// and uniform without needing to know the count in advance.
		var chosen netip.Addr
		seen := 0
		for _, a := range p.all {
			if _, leased := p.holder[a]; leased {
				continue
			}
			seen++
			if rand.IntN(seen) == 0 {
				chosen = a
			}
		}
		return chosen, seen > 0
	}
	for _, a := range p.all {
		if _, leased := p.holder[a]; !leased {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// take records a lease. The caller holds the lock.
func (p *Pool) take(addr netip.Addr, agentID string) {
	p.holder[addr] = agentID
	p.held[agentID] = addr
	if p.mode == Sticky {
		p.sticky[agentID] = addr
	}
}

// Release returns agentID's address to the pool. In Sticky mode the preference
// is kept, so a later reconnect still lands on the same address. Releasing an
// agent that holds nothing is a no-op.
func (p *Pool) Release(agentID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	addr, ok := p.held[agentID]
	if !ok {
		return
	}
	delete(p.held, agentID)
	delete(p.holder, addr)
}

// Holder reports which agent holds addr, if any.
func (p *Pool) Holder(addr netip.Addr) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	holder, ok := p.holder[addr]
	return holder, ok
}

// expand turns one configuration entry into the addresses it names.
func expand(entry string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(entry); err == nil {
		return []netip.Addr{addr}, nil
	}
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return nil, fmt.Errorf("pool: %q is neither an address nor a CIDR prefix", entry)
	}
	prefix = prefix.Masked()

	// For an IPv4 prefix wider than a /31, the first and last addresses are the
	// subnet's network and broadcast addresses. They are skipped because a host
	// on the same link will not reach them normally. An operator who really
	// wants one — a routed block, where they are ordinary addresses — lists it
	// by itself, which takes the literal branch above.
	skipEnds := prefix.Addr().Is4() && prefix.Bits() < 31

	var out []netip.Addr
	for a := prefix.Addr(); prefix.Contains(a); a = a.Next() {
		last := !prefix.Contains(a.Next())
		if skipEnds && (a == prefix.Addr() || last) {
			if last {
				break
			}
			continue
		}
		out = append(out, a)
		if len(out) > MaxAddresses {
			return nil, fmt.Errorf("pool: %q expands past %d addresses", entry, MaxAddresses)
		}
		if last {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pool: %q contains no usable addresses", entry)
	}
	return out, nil
}
