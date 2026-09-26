// Package server publishes agents on leased addresses.
//
// The shape is small because the agent declares its ports: for each declared
// port the server binds one ordinary listener on the leased address, and every
// connection or packet arriving there is carried to the agent, which dials the
// same port on its own target host.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/pool"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/subdomain"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tunnel"
)

// DefaultDenyPorts are the ports the server refuses to publish unless an
// operator says otherwise: SMTP submission and relay.
//
// The reason is deliverability rather than secrecy. A pool address that emits
// spam gets the whole pool listed by the major providers, which costs every
// other agent sharing it. The receive-side mail ports (110, 143, 993, 995)
// carry no such risk and are not on this list — blocking them would be a
// different decision, and an operator who wants it has --deny-ports.
var DefaultDenyPorts = []uint16{25, 465, 587, 2525}

// Authenticator turns an agent's token into a stable identity. The identity is
// what the sticky lease is keyed on, so it must survive a reconnect.
type Authenticator interface {
	// Authenticate returns the agent id for a token, or false if unknown.
	Authenticate(token string) (agentID string, ok bool)
}

// StaticTokens is an Authenticator over a fixed token-to-name map.
type StaticTokens map[string]string

// Authenticate implements Authenticator.
func (t StaticTokens) Authenticate(token string) (string, bool) {
	// An empty token must never match, even if the map somehow holds one:
	// treating it as a valid identity would publish an agent that presented no
	// credential at all.
	if token == "" {
		return "", false
	}
	name, ok := t[token]
	return name, ok
}

// Config configures a Server.
type Config struct {
	// Pool supplies the addresses agents are published on.
	Pool *pool.Pool
	// Auth identifies connecting agents. Required.
	Auth Authenticator
	// DenyPorts are ports that will not be published. Defaults to
	// DefaultDenyPorts when nil.
	DenyPorts []uint16
	// Keepalive is how often the server pings an idle agent. Zero means 15s.
	Keepalive time.Duration
	// Domain, when set, is the DNS zone this server is authoritative for.
	// Every agent is given a random subdomain under it, reported in the lease.
	//
	// Unlike an operator-managed record, this one cannot go stale: the
	// nameserver answers from the live registry, so a name stops resolving the
	// moment its session ends and always points at the address the agent holds
	// right now. That is why random address allocation is compatible with a
	// domain, where an externally managed record would not be.
	Domain string
	// Certs supplies the wildcard certificate for terminated HTTPS. Optional;
	// without it an agent asking for termination is refused that one port and
	// keeps the rest of its lease.
	Certs CertificateSource
	// HTTPSPort is where terminated TLS is bound. Zero means DefaultHTTPSPort.
	HTTPSPort uint16
	// Registry holds the live subdomain bindings the nameserver answers from.
	// Required when Domain is set.
	Registry *subdomain.Registry
	// Logger receives structured events. Defaults to slog.Default().
	Logger *slog.Logger
}

// Server accepts agent sessions and publishes their declared ports.
type Server struct {
	pool      *pool.Pool
	auth      Authenticator
	deny      map[uint16]bool
	keepalive time.Duration
	domain    string
	registry  *subdomain.Registry
	certs     CertificateSource
	httpsPort uint16
	log       *slog.Logger
}

// New builds a Server. It returns an error rather than defaulting when a
// required dependency is missing, because a server with no pool or no
// authenticator would start cleanly and then fail every agent.
func New(cfg Config) (*Server, error) {
	if cfg.Pool == nil {
		return nil, errors.New("server: no address pool configured")
	}
	if cfg.Auth == nil {
		return nil, errors.New("server: no authenticator configured")
	}
	denyList := cfg.DenyPorts
	if denyList == nil {
		denyList = DefaultDenyPorts
	}
	deny := make(map[uint16]bool, len(denyList))
	for _, p := range denyList {
		deny[p] = true
	}
	keepalive := cfg.Keepalive
	if keepalive == 0 {
		keepalive = 15 * time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	httpsPort := cfg.HTTPSPort
	if httpsPort == 0 {
		httpsPort = DefaultHTTPSPort
	}
	if cfg.Domain != "" {
		if err := validateDomain(cfg.Domain); err != nil {
			return nil, err
		}
		if cfg.Registry == nil {
			return nil, errors.New("server: a domain needs a subdomain registry for the nameserver to answer from")
		}
	}
	return &Server{
		pool:      cfg.Pool,
		auth:      cfg.Auth,
		deny:      deny,
		keepalive: keepalive,
		domain:    cfg.Domain,
		registry:  cfg.Registry,
		certs:     cfg.Certs,
		httpsPort: httpsPort,
		log:       log,
	}, nil
}

// Serve accepts sessions until ctx is cancelled or the listener fails.
func (s *Server) Serve(ctx context.Context, ln transport.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		sess, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		wg.Go(func() {
			if err := s.handleSession(ctx, sess); err != nil && ctx.Err() == nil {
				s.log.Info("session ended", "remote", sess.RemoteAddr().String(), "reason", err)
			}
		})
	}
}

// handleSession runs one agent session from handshake to teardown.
func (s *Server) handleSession(ctx context.Context, sess transport.Session) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer sess.CloseWithError("session closed")

	control, udpStream, err := acceptSetupStreams(ctx, sess)
	if err != nil {
		return fmt.Errorf("session setup: %w", err)
	}

	ctl := proto.NewControlConn(control)
	hello, err := readHello(ctl)
	if err != nil {
		return err
	}

	agentID, ok := s.auth.Authenticate(hello.Token)
	if !ok {
		return reject(control, ctl, "unknown token", errors.New("authentication failed"))
	}
	if hello.Version != proto.Version {
		reason := fmt.Sprintf("protocol version %d, server speaks %d", hello.Version, proto.Version)
		return reject(control, ctl, reason, fmt.Errorf("protocol version mismatch: agent %d", hello.Version))
	}

	addrs, err := s.pool.Acquire(agentID)
	if err != nil {
		return reject(control, ctl, err.Error(), err)
	}
	defer s.pool.Release(agentID)

	// The subdomain is bound before the ports so the lease can report it, and
	// released with the session so the name stops resolving the moment the
	// tunnel ends rather than when a cache happens to expire.
	hostname, err := s.bindSubdomain(agentID, addrs)
	if err != nil {
		return reject(control, ctl, err.Error(), err)
	}
	defer s.releaseSubdomain(agentID)

	bound, refused := s.screenPorts(hello.Ports)
	if len(bound) == 0 {
		return reject(control, ctl, "every declared port was refused", errors.New("no publishable ports declared"))
	}

	pub := &publication{
		sess:    sess,
		addrs:   addrs,
		agentID: agentID,
		log:     s.log.With("agent", agentID, "ip", addrList(addrs)),
		conduit: tunnel.NewConduit(sess, udpStream),
	}
	defer pub.close()

	refused = append(refused, pub.bind(ctx, bound)...)

	// Terminated HTTPS is bound after the declared ports, so a conflict on 443
	// is reported against the agent's own declaration rather than against a
	// port it never asked for.
	https, httpsRefusals := s.setUpHTTPS(ctx, pub, hello, hostname, bound)
	refused = append(refused, httpsRefusals...)
	// Screening passed at least one port, but binding can still refuse them
	// all — a port already in use on the host, or a stale socket from a session
	// that has not finished dying. A lease carrying no listeners is worse than
	// no lease: the agent would report success and serve nothing.
	if len(pub.boundSpecs()) == 0 {
		return reject(control, ctl, "no declared port could be bound", errors.New("every declared port failed to bind"))
	}

	if err := ctl.Send(proto.Control{Lease: &proto.Lease{
		IP:           addrs[0].String(),
		IPs:          addrStrings(addrs),
		AgentID:      agentID,
		Bound:        pub.boundSpecs(),
		Refused:      refused,
		KeepaliveSec: int(s.keepalive / time.Second),
		Hostname:     hostname,
		PoolMode:     s.pool.Mode().String(),
		HTTPS:        https,
	}}); err != nil {
		return fmt.Errorf("sending lease: %w", err)
	}

	pub.log.Info("agent published",
		"ports", portspec.Format(pub.boundSpecs()),
		"refused", len(refused),
		"transport_datagrams", sess.MaxDatagramSize() > 0)

	var wg sync.WaitGroup
	wg.Go(func() {
		defer cancel()
		pub.conduit.Run(ctx)
	})
	wg.Go(func() {
		defer cancel()
		pub.pumpAgentPackets(ctx)
	})

	err = s.runControl(ctx, ctl)
	cancel()
	pub.close()
	wg.Wait()
	return err
}

// acceptSetupStreams takes the agent's two opening streams — control and UDP —
// routing each by its kind byte rather than by arrival order, so a transport
// that reorders them does not make the handshake fail mysteriously.
func acceptSetupStreams(ctx context.Context, sess transport.Session) (control, udp transport.Stream, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for range 2 {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return nil, nil, err
		}
		kind, err := proto.ReadStreamKind(stream)
		if err != nil {
			return nil, nil, fmt.Errorf("reading stream kind: %w", err)
		}
		switch kind {
		case proto.KindControl:
			control = stream
		case proto.KindUDP:
			udp = stream
		default:
			return nil, nil, fmt.Errorf("unexpected %s stream during setup", kind)
		}
	}
	if control == nil || udp == nil {
		return nil, nil, errors.New("agent did not open both a control and a UDP stream")
	}
	return control, udp, nil
}

// reject refuses a session with a stated reason and waits for the agent to read
// it.
//
// The wait is the part that is easy to leave out and is load-bearing. Sending
// the message is not enough: handleSession's deferred CloseWithError tears the
// QUIC connection down, and QUIC discards buffered stream data on close, so an
// immediate return delivers a transport error instead of the reason. The agent
// cannot tell that from a network failure, and it retries network failures
// forever — against a server that has already said no.
//
// Draining until the agent closes its end is what confirms it read the message.
// The deadline bounds an agent that never will.
func reject(control transport.Stream, ctl *proto.ControlConn, reason string, cause error) error {
	if err := ctl.Send(proto.Control{Error: &proto.Error{Message: reason}}); err != nil {
		return cause
	}
	control.SetDeadline(time.Now().Add(rejectDrainTimeout))
	io.Copy(io.Discard, control)
	return cause
}

// rejectDrainTimeout bounds how long a refusal waits to be read.
const rejectDrainTimeout = 5 * time.Second

// readHello reads the agent's opening message, refusing anything else.
func readHello(ctl *proto.ControlConn) (*proto.Hello, error) {
	msg, err := ctl.Recv()
	if err != nil {
		return nil, fmt.Errorf("reading hello: %w", err)
	}
	if msg.Hello == nil {
		return nil, errors.New("first control message was not a hello")
	}
	return msg.Hello, nil
}

// screenPorts splits a declaration into what will be published and what will
// not. A denied port costs the agent that port, never its lease: one bad entry
// in a list is a typo, not a reason to refuse the whole tunnel.
func (s *Server) screenPorts(declared []portspec.Spec) (bound []portspec.Spec, refused []proto.Refusal) {
	for _, spec := range declared {
		if s.deny[spec.Port] {
			refused = append(refused, proto.Refusal{
				Spec:   spec,
				Reason: "port is on the server's deny list",
			})
			continue
		}
		bound = append(bound, spec)
	}
	return bound, refused
}

// runControl answers pings and watches for the agent going away.
func (s *Server) runControl(ctx context.Context, ctl *proto.ControlConn) error {
	recv := make(chan proto.Control)
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := ctl.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case recv <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(s.keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			return err
		case msg := <-recv:
			if msg.Ping {
				if err := ctl.Send(proto.Control{Pong: true}); err != nil {
					return err
				}
			}
		case <-ticker.C:
			if err := ctl.Send(proto.Control{Ping: true}); err != nil {
				return err
			}
		}
	}
}

// publication is one agent's published address: its listeners, its UDP flows,
// and the conduit carrying packets to it.
type publication struct {
	sess transport.Session
	// addrs are the leased addresses, at most one per family. Every declared
	// port is bound on every one of them, so a dual-stack lease publishes the
	// same service over IPv4 and IPv6.
	addrs   []netip.Addr
	agentID string
	log     *slog.Logger
	conduit *tunnel.Conduit

	mu        sync.Mutex
	bound     []portspec.Spec
	listeners []net.Listener
	packets   []*net.UDPConn
	closed    bool

	flows flowTable
}

// bind opens a listener for every publishable spec on every leased address.
//
// A port that will not bind is reported as a refusal rather than failing the
// lease: the usual cause is another agent's stale socket or a port in use on
// the host, and the agent's other ports are still worth publishing. A spec is
// refused only when it binds on NO leased address — succeeding on IPv6 while
// IPv4 is taken still publishes the port, and reporting that as a refusal would
// tell the agent a working port is dead.
func (p *publication) bind(ctx context.Context, specs []portspec.Spec) []proto.Refusal {
	var refusals []proto.Refusal
	for _, spec := range specs {
		var lastErr error
		bound := false
		for _, addr := range p.addrs {
			if err := p.bindOne(ctx, spec, addr); err != nil {
				lastErr = err
				continue
			}
			bound = true
		}
		if !bound {
			refusals = append(refusals, proto.Refusal{Spec: spec, Reason: bindReason(lastErr)})
			continue
		}
		p.mu.Lock()
		p.bound = append(p.bound, spec)
		p.mu.Unlock()
	}
	return refusals
}

// bindOne opens one listener for one spec on one address.
func (p *publication) bindOne(ctx context.Context, spec portspec.Spec, addr netip.Addr) error {
	hostPort := net.JoinHostPort(addr.String(), fmt.Sprint(spec.Port))
	switch spec.Proto {
	case portspec.UDP:
		udpAddr, err := net.ResolveUDPAddr("udp", hostPort)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.packets = append(p.packets, conn)
		p.mu.Unlock()
		go p.readUDP(ctx, conn, spec.Port)
		return nil
	default:
		ln, err := net.Listen("tcp", hostPort)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.listeners = append(p.listeners, ln)
		p.mu.Unlock()
		go p.acceptTCP(ctx, ln, spec.Port)
		return nil
	}
}

// addrStrings renders leased addresses for the lease message.
func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

// addrList renders leased addresses for a log field.
func addrList(addrs []netip.Addr) string {
	return strings.Join(addrStrings(addrs), ",")
}

// bindReason renders a bind failure for the agent. The underlying error names
// the address, which is the server's business rather than the agent's, so only
// the operation's outcome is passed on.
func bindReason(err error) string {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return "could not bind: " + opErr.Err.Error()
	}
	return "could not bind: " + err.Error()
}

// boundSpecs returns the specs actually listening.
func (p *publication) boundSpecs() []portspec.Spec {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]portspec.Spec, len(p.bound))
	copy(out, p.bound)
	return out
}

// acceptTCP carries every connection on one published port to the agent.
func (p *publication) acceptTCP(ctx context.Context, ln net.Listener, port uint16) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go p.tunnelTCP(ctx, conn, port)
	}
}

// tunnelTCP opens a stream for one accepted connection and splices it.
func (p *publication) tunnelTCP(ctx context.Context, conn net.Conn, port uint16) {
	stream, err := p.sess.OpenStream(ctx)
	if err != nil {
		conn.Close()
		return
	}
	// The open handshake is bounded: an agent that accepted the stream and then
	// stopped reading would otherwise hold the client's connection open
	// forever.
	stream.SetDeadline(time.Now().Add(20 * time.Second))
	if err := proto.WriteStreamKind(stream, proto.KindTCP); err != nil {
		stream.Close()
		conn.Close()
		return
	}
	if err := proto.WriteTCPOpen(stream, proto.TCPOpen{Port: port, Src: conn.RemoteAddr().String()}); err != nil {
		stream.Close()
		conn.Close()
		return
	}
	res, err := proto.ReadOpenResult(stream)
	if err != nil || res != proto.OpenOK {
		if err == nil {
			p.log.Debug("agent declined a connection", "port", port, "result", res.String())
		}
		stream.Close()
		conn.Close()
		return
	}
	stream.SetDeadline(time.Time{})
	tunnel.Splice(stream, conn)
}

// readUDP carries every packet on one published port to the agent.
func (p *publication) readUDP(ctx context.Context, conn *net.UDPConn, port uint16) {
	buf := make([]byte, proto.MaxUDPPayload)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		flow := p.flows.forClient(port, client, conn)
		frame := proto.AppendUDPFrame(nil, flow.id, port, buf[:n])
		if err := p.conduit.Send(frame); err != nil && ctx.Err() == nil {
			p.log.Debug("dropping a packet to the agent", "port", port, "err", err)
		}
	}
}

// pumpAgentPackets returns packets from the agent to the clients that sent
// them, and evicts flows nothing has used.
func (p *publication) pumpAgentPackets(ctx context.Context) {
	sweep := time.NewTicker(flowSweepInterval)
	defer sweep.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sweep.C:
				p.flows.evictIdle()
			}
		}
	}()

	for {
		frame, err := p.conduit.Recv(ctx)
		if err != nil {
			return
		}
		flowID, _, payload, err := proto.ParseUDPFrame(frame)
		if err != nil {
			continue
		}
		flow, ok := p.flows.byID(flowID)
		if !ok {
			// The flow was evicted while the agent was replying. Dropping is
			// correct: the reply's client is only known through the flow, so
			// there is nowhere to send it.
			continue
		}
		if _, err := flow.conn.WriteToUDP(payload, flow.client); err != nil && ctx.Err() == nil {
			p.log.Debug("dropping a packet to a client", "port", flow.port, "err", err)
		}
	}
}

// close tears the publication down. It is idempotent because both the normal
// exit path and a failed setup call it.
func (p *publication) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	listeners, packets := p.listeners, p.packets
	p.listeners, p.packets = nil, nil
	p.mu.Unlock()

	for _, ln := range listeners {
		ln.Close()
	}
	for _, conn := range packets {
		conn.Close()
	}
	p.conduit.Close()
}
