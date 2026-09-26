// Package subdomain mints and tracks the per-session names agents are
// published under.
//
// A label is random rather than derived from the agent's identity. A derived
// name leaks who is connected to anyone who can guess it, and it collides the
// moment two operators pick the same agent name; a random one does neither, at
// the cost of being unmemorable — which is what the lease message is for.
package subdomain

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// Length is how many characters a minted label has.
//
// 24 base32 characters is exactly 15 random bytes, 120 bits, with no padding to
// strip. That is far past guessable: an attacker enumerating the zone to find
// live tunnels has no better option than the CA transparency logs, which see
// only the wildcard.
const Length = 24

// labelBytes is the random input that yields exactly Length characters.
const labelBytes = Length * 5 / 8

// encoding is lowercase base32 without padding. DNS labels are compared
// case-insensitively, so lowercase avoids two spellings of one name, and the
// alphabet is a strict subset of what a hostname may contain.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewLabel mints a fresh random label.
func NewLabel() (string, error) {
	buf := make([]byte, labelBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("subdomain: generating a label: %w", err)
	}
	return encoding.EncodeToString(buf), nil
}

// Binding is one live subdomain: the addresses it resolves to, and the agent
// holding it.
type Binding struct {
	Label   string
	AgentID string
	Addrs   []netip.Addr
}

// FQDN renders the binding's fully qualified name under a zone.
func (b Binding) FQDN(zone string) string { return b.Label + "." + zone }

// Registry is the live map from label to agent, consulted by the DNS server on
// every query.
//
// It is the authoritative answer for the zone and it changes whenever an agent
// connects or drops, so it is deliberately in memory: persisting it would
// outlive the leases it describes and answer queries with addresses nobody
// holds any more.
type Registry struct {
	mu      sync.RWMutex
	byLabel map[string]*Binding
	byAgent map[string]string
	txt     map[string][]string
	zone    string
}

// NewRegistry builds a registry for a zone. The zone is stored lowercased and
// without a trailing dot, which is the form every lookup normalises to.
func NewRegistry(zone string) *Registry {
	return &Registry{
		byLabel: make(map[string]*Binding),
		byAgent: make(map[string]string),
		txt:     make(map[string][]string),
		zone:    Normalize(zone),
	}
}

// Zone reports the zone this registry is authoritative for.
func (r *Registry) Zone() string { return r.zone }

// Normalize puts a DNS name in the form used for comparison: lowercase, no
// trailing dot. Queries arrive with a trailing dot and arbitrary case, and
// comparing either without normalising is a lookup that silently never matches.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Bind registers a fresh label for an agent and returns it.
//
// Any label the agent held before is released first, so a reconnect does not
// leave its previous name resolving to an address it no longer holds.
func (r *Registry) Bind(agentID string, addrs []netip.Addr) (Binding, error) {
	label, err := NewLabel()
	if err != nil {
		return Binding{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if previous, ok := r.byAgent[agentID]; ok {
		delete(r.byLabel, previous)
	}
	b := &Binding{Label: label, AgentID: agentID, Addrs: append([]netip.Addr(nil), addrs...)}
	r.byLabel[label] = b
	r.byAgent[agentID] = label
	return *b, nil
}

// Release drops an agent's label, so the name stops resolving the moment the
// session ends rather than when a cache happens to expire.
func (r *Registry) Release(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if label, ok := r.byAgent[agentID]; ok {
		delete(r.byLabel, label)
		delete(r.byAgent, agentID)
	}
}

// Lookup resolves a label to its addresses.
func (r *Registry) Lookup(label string) ([]netip.Addr, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.byLabel[Normalize(label)]
	if !ok {
		return nil, false
	}
	return append([]netip.Addr(nil), b.Addrs...), true
}

// Len reports how many labels are live, for diagnostics.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byLabel)
}

// Bindings returns a snapshot of every live subdomain.
//
// The registry is keyed for lookup, because that is what the nameserver does on
// every query; this is the other question an operator has — "what is published
// right now" — which lookup cannot answer without already knowing the label.
// The order is unspecified.
func (r *Registry) Bindings() []Binding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Binding, 0, len(r.byLabel))
	for _, b := range r.byLabel {
		out = append(out, Binding{
			Label:   b.Label,
			AgentID: b.AgentID,
			Addrs:   append([]netip.Addr(nil), b.Addrs...),
		})
	}
	return out
}

// SetTXT publishes TXT values at a name, which is how an ACME DNS-01 challenge
// is answered from this zone.
//
// Values are replaced rather than appended: a stale challenge answered beside a
// fresh one is how a validation fails for no visible reason.
func (r *Registry) SetTXT(name string, values ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txt[Normalize(name)] = append([]string(nil), values...)
}

// ClearTXT removes any TXT values at a name.
func (r *Registry) ClearTXT(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.txt, Normalize(name))
}

// TXT returns the values published at a name.
func (r *Registry) TXT(name string) ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	values, ok := r.txt[Normalize(name)]
	if !ok {
		return nil, false
	}
	return append([]string(nil), values...), true
}
