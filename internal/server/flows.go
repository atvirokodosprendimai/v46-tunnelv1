package server

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// UDP has no connections, so the server has to invent the thing it is missing:
// a handle that survives long enough to route a reply back to the client that
// caused it. A flow is that handle — a client address and the socket it arrived
// on, named by an id the agent echoes in its replies.
const (
	// flowIdleTimeout is how long a flow outlives its last packet. It is longer
	// than a typical DNS or QUIC handshake round trip and shorter than the
	// common NAT mapping lifetime, so a reply that is merely slow still lands.
	flowIdleTimeout = 90 * time.Second
	// flowSweepInterval is how often idle flows are collected.
	flowSweepInterval = 30 * time.Second
)

// flow is one client's conversation with one published UDP port.
type flow struct {
	id     uint64
	port   uint16
	client *net.UDPAddr
	// conn is the published socket the packet arrived on, which is also the
	// socket the reply must leave from: replying from a different one would
	// reach the client with the wrong source port and be discarded.
	conn *net.UDPConn
	// lastSeen is nanoseconds, touched on every packet in either direction, so
	// eviction never has to take the table's lock to read it.
	lastSeen atomic.Int64
}

// touch records activity on the flow.
func (f *flow) touch() { f.lastSeen.Store(time.Now().UnixNano()) }

// flowTable maps between flow ids and client conversations. The zero value is
// ready to use.
type flowTable struct {
	mu     sync.Mutex
	nextID uint64
	byKey  map[string]*flow
	ids    map[uint64]*flow
}

// forClient returns the flow for a client on a port, creating it on first sight.
func (t *flowTable) forClient(port uint16, client *net.UDPAddr, conn *net.UDPConn) *flow {
	key := flowKey(port, client)

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byKey == nil {
		t.byKey = make(map[string]*flow)
		t.ids = make(map[uint64]*flow)
	}
	if f, ok := t.byKey[key]; ok {
		f.touch()
		return f
	}
	t.nextID++
	// The client address is copied because ReadFromUDP reuses its address
	// across calls; keeping the caller's pointer would make every flow in the
	// table name whichever client spoke most recently.
	f := &flow{id: t.nextID, port: port, client: cloneUDPAddr(client), conn: conn}
	f.touch()
	t.byKey[key] = f
	t.ids[f.id] = f
	return f
}

// byID finds a flow by the id the agent echoed back.
func (t *flowTable) byID(id uint64) (*flow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.ids[id]
	if ok {
		f.touch()
	}
	return f, ok
}

// evictIdle drops flows that have seen no traffic for flowIdleTimeout.
func (t *flowTable) evictIdle() {
	cutoff := time.Now().Add(-flowIdleTimeout).UnixNano()

	t.mu.Lock()
	defer t.mu.Unlock()
	for key, f := range t.byKey {
		if f.lastSeen.Load() < cutoff {
			delete(t.byKey, key)
			delete(t.ids, f.id)
		}
	}
}

// len reports how many flows are live, for tests and diagnostics.
func (t *flowTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ids)
}

// flowKey identifies a client conversation on a published port.
func flowKey(port uint16, client *net.UDPAddr) string {
	return strconv.Itoa(int(port)) + "|" + client.String()
}

// cloneUDPAddr copies an address so it is not invalidated by the next read.
func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	out := &net.UDPAddr{Port: a.Port, Zone: a.Zone}
	out.IP = append(net.IP(nil), a.IP...)
	return out
}
