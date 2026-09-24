package agent

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tunnel"
)

// udpLocals keeps one connected local socket per tunneled UDP flow.
//
// A socket per flow rather than one per port is what makes replies routable.
// The local service answers on the socket the request came from, so keeping
// them separate is how the agent knows which client a reply belongs to — with a
// single shared socket every flow's replies would arrive indistinguishable.
type udpLocals struct {
	idle time.Duration

	mu      sync.Mutex
	conns   map[uint64]*localUDP
	closed  bool
	sweeper sync.Once
}

// localUDP is one flow's socket and the goroutine reading its replies.
type localUDP struct {
	conn     *net.UDPConn
	port     uint16
	reader   sync.Once
	lastSeen time.Time
}

// get returns the socket for a flow, creating it with dial on first use.
func (l *udpLocals) get(flowID uint64, port uint16, dial func() (*net.UDPConn, error)) (*net.UDPConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, net.ErrClosed
	}
	if l.conns == nil {
		l.conns = make(map[uint64]*localUDP)
	}
	if existing, ok := l.conns[flowID]; ok {
		existing.lastSeen = time.Now()
		return existing.conn, nil
	}
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	l.conns[flowID] = &localUDP{conn: conn, port: port, lastSeen: time.Now()}
	return conn, nil
}

// startReader ensures exactly one goroutine is returning this flow's replies.
func (l *udpLocals) startReader(flowID uint64, port uint16, conduit *tunnel.Conduit, log *slog.Logger) {
	l.mu.Lock()
	entry, ok := l.conns[flowID]
	l.mu.Unlock()
	if !ok {
		return
	}
	entry.reader.Do(func() {
		go func() {
			buf := make([]byte, proto.MaxUDPPayload)
			for {
				// The deadline is what retires a flow whose local service has
				// gone quiet: without it the goroutine and its socket would
				// live as long as the session.
				entry.conn.SetReadDeadline(time.Now().Add(l.idle))
				n, err := entry.conn.Read(buf)
				if err != nil {
					l.drop(flowID)
					return
				}
				frame := proto.AppendUDPFrame(nil, flowID, port, buf[:n])
				if err := conduit.Send(frame); err != nil {
					log.Debug("dropping a UDP reply", "port", port, "err", err)
					l.drop(flowID)
					return
				}
			}
		}()
	})
}

// drop closes and forgets one flow's socket.
func (l *udpLocals) drop(flowID uint64) {
	l.mu.Lock()
	entry, ok := l.conns[flowID]
	delete(l.conns, flowID)
	l.mu.Unlock()
	if ok {
		entry.conn.Close()
	}
}

// closeAll releases every socket. Further gets fail rather than reopening, so a
// session teardown cannot race a late packet into a new local connection.
func (l *udpLocals) closeAll() {
	l.mu.Lock()
	l.closed = true
	conns := l.conns
	l.conns = nil
	l.mu.Unlock()
	for _, entry := range conns {
		entry.conn.Close()
	}
}

// sweepIdle closes sockets that have received nothing for the idle period. The
// read deadline retires a flow whose local service went quiet; this retires one
// whose remote client did.
func (l *udpLocals) sweepIdle(ctx context.Context) {
	ticker := time.NewTicker(l.idle / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-l.idle)
			l.mu.Lock()
			var stale []*localUDP
			for id, entry := range l.conns {
				if entry.lastSeen.Before(cutoff) {
					stale = append(stale, entry)
					delete(l.conns, id)
				}
			}
			l.mu.Unlock()
			for _, entry := range stale {
				entry.conn.Close()
			}
		}
	}
}
