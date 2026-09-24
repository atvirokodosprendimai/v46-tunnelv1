package pool

import (
	"net/netip"
	"testing"
)

// acquireOne leases and returns the single address expected from a
// single-family pool.
//
// Most tests predate dual-stack leasing and are about allocation policy, not
// about families; this keeps them reading as "one agent, one address" while the
// API returns a set. A test that means to exercise two families calls Acquire
// directly.
func acquireOne(t *testing.T, p *Pool, agentID string) netip.Addr {
	t.Helper()
	addrs, err := p.Acquire(agentID)
	if err != nil {
		t.Fatalf("Acquire(%s): %v", agentID, err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Acquire(%s) returned %d addresses, want 1; this helper is for single-family pools", agentID, len(addrs))
	}
	return addrs[0]
}
