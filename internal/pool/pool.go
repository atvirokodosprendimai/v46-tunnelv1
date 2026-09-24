// Package pool hands out the addresses agents are published on.
//
// The addresses are assumed to already exist on the host — put on an interface
// by the operator, or routed to it as a block. The pool only tracks which are
// free, which keeps the server out of privileged netlink work and means a crash
// leaves no half-configured interface behind.
//
// A lease is a SET of addresses, at most one per family. A pool holding both
// IPv4 and IPv6 gives an agent one of each, so a hostname pointed at it can
// carry both an A and an AAAA record — which is what a dual-stack service
// needs, and what leasing a single address cannot express.
package pool

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
)

// MaxAddresses bounds how many addresses one pool may hold. A mistyped prefix
// is the realistic way to exceed it — "10.0.0.0/8" is sixteen million
// addresses, and materialising them would exhaust memory long before anyone
// noticed the typo.
const MaxAddresses = 65536

// ErrExhausted reports that no family in the pool has a free address.
var ErrExhausted = errors.New("pool: no free addresses")

// Family distinguishes the two address families a lease may hold one of.
type Family int

// The address families.
const (
	IPv4 Family = iota
	IPv6
)

// String names the family for logs.
func (f Family) String() string {
	if f == IPv6 {
		return "ipv6"
	}
	return "ipv4"
}

// familyOf reports which family an address belongs to. An IPv4-mapped IPv6
// address counts as IPv4, because that is the address a client actually reaches.
func familyOf(a netip.Addr) Family {
	if a.Is4() || a.Is4In6() {
		return IPv4
	}
	return IPv6
}

// Mode says how a free address is chosen for an agent.
type Mode int

const (
	// Sticky gives a reconnecting agent the addresses it held last, while they
	// are still free.
	//
	// This is the default because everything pointed at a published address
	// caches it — DNS records, firewall rules, a client's config file — so an
	// address that changes on every reconnect quietly breaks callers that are
	// doing nothing wrong.
	Sticky Mode = iota

	// Random chooses uniformly among the free addresses of each family and
	// remembers nothing, so a reconnecting agent generally lands somewhere new.
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
	// families lists which families the pool actually holds, in the order they
	// first appear. A lease takes one address from each.
	families []Family
	// holder maps a leased address to the agent holding it.
	holder map[netip.Addr]string
	// held maps an agent to the addresses it currently holds. It is what makes
	// a repeated Acquire idempotent in both modes, and Release a lookup rather
	// than a scan.
	held map[string][]netip.Addr
	// sticky remembers the last address each agent held in each family,
	// including after the lease is released. It is the memory that makes a
	// reconnect keep its addresses, and it is deliberately never pruned,
	// because an agent that disconnects overnight is exactly the case it exists
	// for. Unused in Random mode, which is the whole of what Random means.
	sticky map[string]map[Family]netip.Addr
}

// New builds a pool from a list of addresses and CIDR prefixes, in the order
// given. A bare address is taken literally; a prefix is expanded.
func New(entries []string, mode Mode) (*Pool, error) {
	p := &Pool{
		mode:   mode,
		holder: make(map[netip.Addr]string),
		held:   make(map[string][]netip.Addr),
		sticky: make(map[string]map[Family]netip.Addr),
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
			if fam := familyOf(a); !slices.Contains(p.families, fam) {
				p.families = append(p.families, fam)
			}
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

// Families reports which address families the pool holds, so a caller can say
// whether leases will be dual-stack.
func (p *Pool) Families() []Family { return slices.Clone(p.families) }

// Free reports how many addresses are currently unleased.
func (p *Pool) Free() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.all) - len(p.holder)
}

// Acquire leases one address per family to agentID.
//
// A pool holding only one family returns one address; a dual-stack pool returns
// two. It succeeds if ANY family had something free, because half a dual-stack
// lease still publishes the agent — the alternative is refusing a working IPv6
// lease because the IPv4 half ran out.
//
// An agent that acquires twice without releasing — a reconnect racing its own
// dead session's cleanup — gets the same addresses back rather than a second
// set, in either mode, so a flapping agent cannot drain the pool.
func (p *Pool) Acquire(agentID string) ([]netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if current, ok := p.held[agentID]; ok {
		return slices.Clone(current), nil
	}

	var leased []netip.Addr
	for _, fam := range p.families {
		addr, ok := p.pickFor(agentID, fam)
		if !ok {
			continue
		}
		p.take(addr, agentID, fam)
		leased = append(leased, addr)
	}
	if len(leased) == 0 {
		return nil, ErrExhausted
	}
	p.held[agentID] = leased
	return slices.Clone(leased), nil
}

// pickFor chooses one free address of a family. The caller holds the lock.
func (p *Pool) pickFor(agentID string, fam Family) (netip.Addr, bool) {
	if p.mode == Sticky {
		if want, ok := p.sticky[agentID][fam]; ok {
			if _, leased := p.holder[want]; !leased {
				return want, true
			}
		}
	}
	if p.mode == Random {
		// Reservoir sampling over this family's free addresses: one pass, no
		// allocation, and uniform without needing the count in advance.
		var chosen netip.Addr
		seen := 0
		for _, a := range p.all {
			if familyOf(a) != fam {
				continue
			}
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
		if familyOf(a) != fam {
			continue
		}
		if _, leased := p.holder[a]; !leased {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// take records a lease on one address. The caller holds the lock.
func (p *Pool) take(addr netip.Addr, agentID string, fam Family) {
	p.holder[addr] = agentID
	if p.mode == Sticky {
		if p.sticky[agentID] == nil {
			p.sticky[agentID] = make(map[Family]netip.Addr)
		}
		p.sticky[agentID][fam] = addr
	}
}

// Release returns every address agentID holds. In Sticky mode the preferences
// are kept, so a later reconnect still lands on the same addresses. Releasing
// an agent that holds nothing is a no-op.
func (p *Pool) Release(agentID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	addrs, ok := p.held[agentID]
	if !ok {
		return
	}
	delete(p.held, agentID)
	for _, addr := range addrs {
		delete(p.holder, addr)
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
	// on the same link will not reach them normally. IPv6 has no broadcast
	// address and no such convention, so nothing is skipped there. An operator
	// who really wants one — a routed block, where they are ordinary addresses
	// — lists it by itself, which takes the literal branch above.
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
