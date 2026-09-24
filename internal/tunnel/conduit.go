// Package tunnel holds the pieces the server and the agent both need: the UDP
// conduit that hides the datagram/stream split, and the connection splice that
// joins a tunneled stream to a local socket.
package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
)

// Conduit carries framed UDP packets between the server and the agent.
//
// It exists because UDP has two possible paths and the callers must not have to
// know which they are on. Over QUIC a packet rides an unreliable datagram,
// which preserves the semantics the application inside the tunnel chose. Over
// the WebSocket fallback, and for any packet too large for a single datagram,
// it rides a length-prefixed record on one dedicated stream instead — delivered
// reliably, which is not what UDP promises but is better than dropping it.
//
// A Conduit is safe for concurrent use.
type Conduit struct {
	sess   transport.Session
	stream transport.Stream

	// writeMu serialises stream writes. A frame is two writes — the length
	// prefix and the body — and interleaving two frames' writes would
	// desynchronise the reader permanently rather than lose one packet.
	writeMu sync.Mutex

	in       chan []byte
	closeErr chan error
	once     sync.Once
}

// inboundBuffer is how many received frames may queue before the reader drops.
// UDP is lossy by contract, so a full queue drops rather than applying
// backpressure to the whole session — one slow local socket must not stall the
// tunnel's TCP connections.
const inboundBuffer = 256

// NewConduit builds a conduit over a session and its dedicated UDP stream.
func NewConduit(sess transport.Session, stream transport.Stream) *Conduit {
	return &Conduit{
		sess:     sess,
		stream:   stream,
		in:       make(chan []byte, inboundBuffer),
		closeErr: make(chan error, 2),
	}
}

// Run pumps both inbound sources until ctx is done or the session dies. It
// returns the error that ended it.
func (c *Conduit) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() { c.readStream(ctx) })
	if c.sess.MaxDatagramSize() > 0 {
		wg.Go(func() { c.readDatagrams(ctx) })
	}

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-c.sess.Context().Done():
		err = c.sess.Context().Err()
	case err = <-c.closeErr:
	}
	cancel()
	// Closing the stream is what unblocks readStream, which is parked in a
	// Read that no context can interrupt.
	c.once.Do(func() { c.stream.Close() })
	wg.Wait()
	return err
}

// readStream pumps length-prefixed frames off the dedicated UDP stream.
func (c *Conduit) readStream(ctx context.Context) {
	for {
		frame, err := proto.ReadUDPStreamFrame(c.stream)
		if err != nil {
			select {
			case c.closeErr <- err:
			default:
			}
			return
		}
		select {
		case c.in <- frame:
		case <-ctx.Done():
			return
		default:
			// Queue full: drop, as UDP allows. Blocking here would let one
			// unresponsive local socket stall every other flow.
		}
	}
}

// readDatagrams pumps unreliable frames off the session.
func (c *Conduit) readDatagrams(ctx context.Context) {
	for {
		frame, err := c.sess.ReceiveDatagram(ctx)
		if err != nil {
			select {
			case c.closeErr <- err:
			default:
			}
			return
		}
		select {
		case c.in <- frame:
		case <-ctx.Done():
			return
		default:
		}
	}
}

// Recv returns the next framed UDP packet from either path.
func (c *Conduit) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame := <-c.in:
		return frame, nil
	}
}

// Send delivers one framed UDP packet, preferring the unreliable path.
//
// The datagram attempt is allowed to fail: a peer that never advertised
// datagram support, or a frame larger than one packet, both fall through to the
// stream rather than becoming a lost packet the caller cannot see.
func (c *Conduit) Send(frame []byte) error {
	if maxFrame := c.sess.MaxDatagramSize(); maxFrame > 0 && len(frame) <= maxFrame {
		err := c.sess.SendDatagram(frame)
		if err == nil {
			return nil
		}
		if !errors.Is(err, transport.ErrNoDatagrams) && c.sess.Context().Err() != nil {
			// The session is gone; the stream will not do any better.
			return err
		}
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return proto.WriteUDPStreamFrame(c.stream, frame)
}

// Close shuts the conduit's stream down.
func (c *Conduit) Close() error {
	c.once.Do(func() { c.stream.Close() })
	return nil
}

// Splice joins a tunneled stream to a local connection, copying in both
// directions until either side ends.
//
// Both directions are torn down together rather than honouring TCP half-close.
// Half-close would be more faithful, but the two transports disagree about what
// closing one direction of a multiplexed stream means — QUIC closes the send
// side, yamux closes both — so honouring it on one and not the other would make
// the tunnel's behaviour depend on which transport happened to be negotiated.
// Tearing both down is the behaviour that is the same either way.
func Splice(stream transport.Stream, local net.Conn) {
	var once sync.Once
	stop := func() {
		once.Do(func() {
			stream.Close()
			local.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		defer stop()
		io.Copy(local, stream)
	})
	wg.Go(func() {
		defer stop()
		io.Copy(stream, local)
	})
	wg.Wait()
}
