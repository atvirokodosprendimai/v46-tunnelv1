// Package pool hands out the addresses agents are published on.
//
// The addresses are assumed to already exist on the host — put on an interface
// by the operator, or routed to it as a block. The pool only tracks which are
// free, which keeps the server out of privileged netlink work and means a crash
// leaves no half-configured interface behind.
//
// Leases are sticky: an agent that reconnects gets the address it had before,
// while it is still free. That is not a convenience. Everything pointed at a
// published address caches it — DNS records, firewall rules, a client's config
// file — so an address that changes on every reconnect quietly breaks all of
// them.
package pool

import (
	"errors"
	"fmt"
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

// Pool is a set of addresses and the leases held on them. It is safe for
// concurrent use.
type Pool struct {
	mu sync.Mutex
	// all preserves configuration order, so allocation is predictable and an
	// operator reading the logs sees addresses handed out in the order they
	// wrote them.
	all []netip.Addr
	// holder maps a leased address to the agent holding it.
	holder map[netip.Addr]string
	// sticky remembers the last address each agent held, including after the
	// lease is released. It is the memory that makes a reconnect keep its
	// address; it is deliberately never pruned, because an agent that
	// disconnects overnight is exactly the case it exists for.
	sticky map[string]netip.Addr
}

// New builds a pool from a list of addresses and CIDR prefixes, in the order
// given. A bare address is taken literally; a prefix is expanded.
func New(entries []string) (*Pool, error) {
	p := &Pool{holder: make(map[netip.Addr]string), sticky: make(map[string]netip.Addr)}
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

// Size reports how many addresses the pool holds.
func (p *Pool) Size() int { return len(p.all) }

// Free reports how many addresses are currently unleased.
func (p *Pool) Free() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.all) - len(p.holder)
}

// Acquire leases an address to agentID, preferring the one it held last.
//
// An agent that acquires twice without releasing — a reconnect racing its own
// dead session's cleanup — gets the same address back rather than a second one,
// so a flapping agent cannot drain the pool.
func (p *Pool) Acquire(agentID string) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if want, ok := p.sticky[agentID]; ok {
		if holder, leased := p.holder[want]; !leased || holder == agentID {
			p.holder[want] = agentID
			return want, nil
		}
	}
	for _, a := range p.all {
		if _, leased := p.holder[a]; leased {
			continue
		}
		p.holder[a] = agentID
		p.sticky[agentID] = a
		return a, nil
	}
	return netip.Addr{}, ErrExhausted
}

// Release returns agentID's address to the pool. The sticky preference is kept,
// so a later reconnect still lands on the same address. Releasing an agent that
// holds nothing is a no-op.
func (p *Pool) Release(agentID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, holder := range p.holder {
		if holder == agentID {
			delete(p.holder, addr)
		}
	}
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
