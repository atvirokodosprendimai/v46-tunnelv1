// Package transport is the seam between the tunnel protocol and the wire it
// runs on.
//
// Two implementations exist. QUIC is the primary: it gives a stream per
// tunneled connection and real datagrams for UDP, so a lossy moment on one
// tunneled connection does not stall the others and a tunneled UDP packet stays
// unreliable, which is the shape the thing being tunneled expects. The
// WebSocket fallback exists for networks that will not pass QUIC at all —
// everything there rides one TCP connection, so it trades those two properties
// for reach.
//
// Keeping the seam this narrow is what lets the server and agent be written
// once: neither of them names QUIC or WebSocket anywhere.
package transport

import (
	"context"
	"io"
	"net"
	"time"
)

// Stream is one reliable, ordered, bidirectional byte stream within a session.
// It carries either the control channel or exactly one tunneled TCP connection.
type Stream interface {
	io.ReadWriteCloser
	// SetDeadline bounds a handshake that would otherwise hang forever against
	// a peer that connected and then went quiet.
	SetDeadline(t time.Time) error
}

// Session is a live multiplexed connection between the server and one agent.
//
// Implementations must be safe for concurrent use: the server opens a stream
// per accepted connection from one goroutine while another is sending
// datagrams, and serialising that at the call site would make every transport
// as slow as the slowest.
type Session interface {
	// OpenStream opens a new outbound stream.
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream accepts the next inbound stream.
	AcceptStream(ctx context.Context) (Stream, error)
	// SendDatagram sends one unreliable frame. It returns ErrNoDatagrams when
	// the transport has none, and an error when the frame is too large — both
	// of which the caller answers by falling back to the UDP stream rather than
	// by dropping the packet.
	SendDatagram(frame []byte) error
	// ReceiveDatagram blocks for the next unreliable frame. On a transport
	// without datagrams it blocks until ctx is done, so a caller can select on
	// it unconditionally instead of branching on transport identity.
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	// MaxDatagramSize reports the largest frame SendDatagram will accept, or 0
	// when the transport has no datagram support at all.
	MaxDatagramSize() int
	// RemoteAddr is the peer's address, for logs and rate limiting.
	RemoteAddr() net.Addr
	// CloseWithError ends the session, telling the peer why. The reason reaches
	// the other side, which is what separates a refusal from a network failure.
	CloseWithError(reason string) error
	// Context is cancelled when the session dies, whichever side ended it.
	Context() context.Context
}

// Listener accepts incoming agent sessions.
type Listener interface {
	Accept(ctx context.Context) (Session, error)
	Addr() net.Addr
	Close() error
}

// Dialer opens a session to a server. Name identifies the transport in logs and
// in the agent's fallback reporting, so an operator can tell which of the two
// actually carried the session.
type Dialer interface {
	Dial(ctx context.Context, addr string) (Session, error)
	Name() string
}

// ErrNoDatagrams reports a transport with no unreliable-frame support. It is a
// sentinel rather than a generic error because the caller's response is
// specific: send the frame over the UDP stream instead.
var ErrNoDatagrams = errNoDatagrams{}

type errNoDatagrams struct{}

func (errNoDatagrams) Error() string { return "transport: datagrams unsupported" }
