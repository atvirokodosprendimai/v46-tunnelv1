// Package quictp implements the tunnel transport over QUIC.
//
// This is the primary transport, and the reason is structural rather than a
// preference for the newer protocol. QUIC gives one flow-controlled stream per
// tunneled TCP connection, so loss on one tunneled connection does not stall
// the rest; and RFC 9221 datagrams let a tunneled UDP packet stay unreliable
// and unordered, which is what the application inside it was written against.
// Carrying either of those over a single TCP connection changes the behaviour
// of what is being tunneled, which is why the WebSocket transport is a fallback
// and not an equal.
package quictp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
)

// ALPN is the application protocol negotiated in the TLS handshake. Naming it
// keeps the tunnel from being answered by an unrelated QUIC service sharing the
// port, and makes a misconfiguration fail in the handshake rather than at the
// first control message.
const ALPN = "v46tun/1"

// maxDatagramFrame bounds a single QUIC datagram's payload. QUIC datagrams
// cannot be fragmented, so the frame has to fit in one packet: this is a
// conservative figure that holds under a 1280-byte IPv6 minimum MTU with room
// for QUIC and IP headers. A UDP packet that does not fit goes over the UDP
// stream instead — the caller's job, not this package's.
const maxDatagramFrame = 1100

// applicationCloseCode is the QUIC application error code used for every
// deliberate close. The human-readable reason travels beside it.
const applicationCloseCode quic.ApplicationErrorCode = 0x100

// config returns the QUIC settings both ends must agree on.
func config() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		// A tunnel session is long-lived and often idle between connections, so
		// it needs keepalives: without them a NAT on the path silently forgets
		// the mapping and the agent looks connected until the first real packet.
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
	}
}

// session adapts a QUIC connection to transport.Session.
type session struct{ conn *quic.Conn }

// Wrap adapts an established QUIC connection to the transport interface. It is
// exported so a caller that built its own quic.Transport — to share one UDP
// socket across roles, say — can still use this package's adapters.
func Wrap(conn *quic.Conn) transport.Session { return &session{conn: conn} }

func (s *session) OpenStream(ctx context.Context) (transport.Stream, error) {
	return s.conn.OpenStreamSync(ctx)
}

func (s *session) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return s.conn.AcceptStream(ctx)
}

func (s *session) SendDatagram(frame []byte) error { return s.conn.SendDatagram(frame) }

func (s *session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.conn.ReceiveDatagram(ctx)
}

// MaxDatagramSize reports the datagram budget, or 0 when the peer did not
// advertise datagram support — an older agent, or one behind a middlebox that
// stripped the transport parameter. Reporting 0 rather than the constant is
// what makes the caller fall back to the UDP stream instead of sending frames
// into a channel the peer will never read.
func (s *session) MaxDatagramSize() int {
	if !s.conn.ConnectionState().SupportsDatagrams.Remote {
		return 0
	}
	return maxDatagramFrame
}

func (s *session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *session) CloseWithError(reason string) error {
	return s.conn.CloseWithError(applicationCloseCode, reason)
}

func (s *session) Context() context.Context { return s.conn.Context() }

// Listener accepts agent sessions over QUIC.
type Listener struct{ ln *quic.Listener }

// Listen starts a QUIC listener on addr. tlsConf must carry the server's
// certificate; its ALPN list is set here so a caller cannot accidentally omit
// it and get a handshake that succeeds against the wrong protocol.
func Listen(addr string, tlsConf *tls.Config) (*Listener, error) {
	conf := tlsConf.Clone()
	conf.NextProtos = []string{ALPN}
	ln, err := quic.ListenAddr(addr, conf, config())
	if err != nil {
		return nil, err
	}
	return &Listener{ln: ln}, nil
}

// Accept returns the next agent session.
func (l *Listener) Accept(ctx context.Context) (transport.Session, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return Wrap(conn), nil
}

// Addr is the address the listener is bound to.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops accepting.
func (l *Listener) Close() error { return l.ln.Close() }

// Dialer opens agent sessions over QUIC.
type Dialer struct {
	// TLSConfig authenticates the server. Its ALPN list is overwritten.
	TLSConfig *tls.Config
}

// Name identifies this transport in logs and in the agent's fallback report.
func (Dialer) Name() string { return "quic" }

// Dial opens a session to the server at addr.
func (d Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	conf := d.TLSConfig.Clone()
	conf.NextProtos = []string{ALPN}
	conn, err := quic.DialAddr(ctx, addr, conf, config())
	if err != nil {
		return nil, err
	}
	return Wrap(conn), nil
}

// IsDatagramTooLarge reports whether err is QUIC's refusal of an oversized
// datagram, as opposed to a dead session. The two need different answers —
// resend over the UDP stream, versus give up — and they arrive through the same
// return value.
func IsDatagramTooLarge(err error) bool {
	var tooLarge *quic.DatagramTooLargeError
	return errors.As(err, &tooLarge)
}
