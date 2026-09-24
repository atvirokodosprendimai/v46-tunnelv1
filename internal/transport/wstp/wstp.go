// Package wstp implements the tunnel transport over a WebSocket (WSS),
// multiplexed with yamux.
//
// This is the fallback, taken only when QUIC cannot get through — a network
// that blocks UDP outright, or an egress proxy that passes nothing but HTTP.
// The cost is real and worth naming: every tunneled connection here shares one
// TCP connection, so loss affecting any of them stalls all of them, and a
// tunneled UDP packet is delivered reliably and in order because there is no
// unreliable channel to put it on. Applications that chose UDP did not ask for
// that. Prefer QUIC; reach for this when the alternative is no tunnel at all.
package wstp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
)

// Subprotocol is the WebSocket subprotocol both ends negotiate, so a stray
// client reaching the endpoint fails at the handshake rather than at the first
// yamux frame.
const Subprotocol = "v46tun.v1"

// Path is the HTTP path the server serves the fallback on.
const Path = "/tunnel"

// yamuxConfig returns the multiplexer settings both ends use.
func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	// yamux's own keepalive is what notices a silently dropped TCP connection;
	// without it a half-open session looks healthy until a real write fails.
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.ConnectionWriteTimeout = 30 * time.Second
	// yamux logs to stderr by default, which would interleave unstructured
	// lines into a structured log. Errors reach the caller through the API
	// instead, so discarding these loses nothing actionable.
	cfg.LogOutput = io.Discard
	return cfg
}

// session adapts a yamux session to transport.Session.
type session struct {
	mux    *yamux.Session
	remote net.Addr
	ctx    context.Context
	cancel context.CancelFunc
}

func newSession(mux *yamux.Session, remote net.Addr) *session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{mux: mux, remote: remote, ctx: ctx, cancel: cancel}
	// yamux reports death through a channel rather than a context; bridging it
	// here is what lets callers treat both transports identically.
	go func() {
		<-mux.CloseChan()
		cancel()
	}()
	return s
}

func (s *session) OpenStream(ctx context.Context) (transport.Stream, error) {
	type result struct {
		stream *yamux.Stream
		err    error
	}
	// yamux has no context-aware open, so the call is raced against ctx. The
	// goroutine cannot leak: OpenStream always returns once the session dies,
	// and the buffered channel means it never blocks on a send nobody reads.
	ch := make(chan result, 1)
	go func() {
		stream, err := s.mux.OpenStream()
		ch <- result{stream, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.stream, nil
	}
}

func (s *session) AcceptStream(ctx context.Context) (transport.Stream, error) {
	type result struct {
		stream *yamux.Stream
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		stream, err := s.mux.AcceptStream()
		ch <- result{stream, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.stream, nil
	}
}

// SendDatagram always refuses: yamux offers no unreliable channel. The caller
// answers ErrNoDatagrams by using the UDP stream, so this is the mechanism by
// which UDP still works here, not a gap.
func (s *session) SendDatagram([]byte) error { return transport.ErrNoDatagrams }

// ReceiveDatagram blocks until ctx is done. A caller can select on it
// unconditionally rather than branching on which transport it holds.
func (s *session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// MaxDatagramSize reports 0, the signal that this transport has no datagrams.
func (s *session) MaxDatagramSize() int { return 0 }

func (s *session) RemoteAddr() net.Addr { return s.remote }

func (s *session) CloseWithError(string) error {
	// yamux carries no close reason, so the reason is dropped here rather than
	// pretended: callers that need the peer to learn why send a proto.Error on
	// the control stream before closing.
	s.cancel()
	return s.mux.Close()
}

func (s *session) Context() context.Context { return s.ctx }

// Handler serves the fallback endpoint, turning each accepted WebSocket into a
// session delivered to Accept.
type Handler struct {
	sessions chan transport.Session
	ctx      context.Context
	cancel   context.CancelFunc
	addr     net.Addr
}

// NewHandler creates a handler. Mount it at Path on the server's HTTPS router.
func NewHandler(addr net.Addr) *Handler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Handler{sessions: make(chan transport.Session), ctx: ctx, cancel: cancel, addr: addr}
}

// ServeHTTP accepts one WebSocket and hands its multiplexed session to Accept.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
	if err != nil {
		return
	}
	if c.Subprotocol() != Subprotocol {
		c.Close(websocket.StatusPolicyViolation, "expected subprotocol "+Subprotocol)
		return
	}
	// The read limit exists for message-oriented use; yamux frames the stream
	// itself, so lifting it is required rather than permissive.
	c.SetReadLimit(-1)

	netConn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	mux, err := yamux.Server(netConn, yamuxConfig())
	if err != nil {
		c.Close(websocket.StatusInternalError, "multiplexer setup failed")
		return
	}
	sess := newSession(mux, remoteAddr(r))

	select {
	case h.sessions <- sess:
		// Hold the HTTP handler open for the session's life: returning would
		// let net/http tear the hijacked connection down underneath yamux.
		<-sess.Context().Done()
	case <-h.ctx.Done():
		mux.Close()
	case <-r.Context().Done():
		mux.Close()
	}
}

// Accept returns the next agent session that arrived over the fallback.
func (h *Handler) Accept(ctx context.Context) (transport.Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.ctx.Done():
		return nil, net.ErrClosed
	case sess := <-h.sessions:
		return sess, nil
	}
}

// Addr reports the address the enclosing HTTPS server is bound to.
func (h *Handler) Addr() net.Addr { return h.addr }

// Close stops accepting new sessions. Sessions already running are unaffected.
func (h *Handler) Close() error {
	h.cancel()
	return nil
}

// Dialer opens agent sessions over WSS.
type Dialer struct {
	// TLSConfig authenticates the server.
	TLSConfig *tls.Config
}

// Name identifies this transport in logs and in the agent's fallback report.
func (Dialer) Name() string { return "wss" }

// Dial opens a session to the server. addr is a host:port; the WSS URL is
// derived from it so an agent configures one address for both transports.
func (d Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: d.TLSConfig.Clone()},
	}
	c, _, err := websocket.Dial(ctx, "wss://"+addr+Path, &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{Subprotocol},
	})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(-1)

	netConn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	mux, err := yamux.Client(netConn, yamuxConfig())
	if err != nil {
		c.Close(websocket.StatusInternalError, "multiplexer setup failed")
		return nil, err
	}
	remote, _ := net.ResolveTCPAddr("tcp", addr)
	return newSession(mux, remote), nil
}

// remoteAddr extracts the client's address from a request for logging.
func remoteAddr(r *http.Request) net.Addr {
	if addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr); err == nil {
		return addr
	}
	return stringAddr(r.RemoteAddr)
}

// stringAddr carries an address that would not parse, so a log line still says
// who connected instead of saying nothing.
type stringAddr string

func (stringAddr) Network() string  { return "tcp" }
func (a stringAddr) String() string { return string(a) }
