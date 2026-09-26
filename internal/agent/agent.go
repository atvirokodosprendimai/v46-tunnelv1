// Package agent connects to a tunnel server and serves the ports it declared.
//
// Everything the agent does is a dial to its own target host: a tunneled TCP
// stream becomes a connection to the same port on 127.0.0.1, and a tunneled UDP
// frame becomes a packet to the same port. The agent never listens on anything.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tunnel"
)

// Config configures an Agent.
type Config struct {
	// Server is the host:port of the tunnel server.
	Server string
	// Token authenticates this agent and keys its sticky address.
	Token string
	// Ports are the local ports to publish.
	Ports []portspec.Spec
	// Target is the host the agent dials locally. Defaults to 127.0.0.1.
	//
	// It stays configurable because the alternative is worse: an operator who
	// needs to reach a service on another host would otherwise run a second
	// forwarder to fake a local port, which is more moving parts for the same
	// exposure.
	Target string
	// DialTimeout bounds a local dial. Zero means 10s.
	DialTimeout time.Duration
	// UDPIdleTimeout is how long an idle local UDP socket is kept. Zero means 90s.
	UDPIdleTimeout time.Duration
	// ServeDir, when set, publishes this directory over the tunnel as a
	// read-only HTTP file server on ServePort.
	//
	// It is served straight off the tunneled stream rather than by starting a
	// local listener, so the directory has no port on the agent's own machine
	// and is reachable only through the tunnel.
	ServeDir string
	// ServePort is the published port the directory is served on. It is added
	// to Ports automatically when ServeDir is set, and ignored when ACME is
	// enabled — a certificate moves the directory to 80 and 443.
	ServePort uint16
	// ACME, when enabled, obtains a certificate and serves ServeDir over TLS.
	ACME ACMEConfig
	// Logger receives structured events. Defaults to slog.Default().
	Logger *slog.Logger
}

// Agent is one connection's worth of tunnel client.
type Agent struct {
	cfg     Config
	target  string
	timeout time.Duration
	udpIdle time.Duration
	log     *slog.Logger

	// files serves ServeDir when one was configured, and is nil otherwise. It
	// is built in Run rather than New, because with ACME the hostname to
	// request a certificate for may come from the server's lease.
	files *fileServer

	// allowed is the set the agent itself will dial. It is derived from the
	// declared ports and enforced here as well as on the server, because the
	// agent is the side that actually reaches localhost: a server that was
	// compromised, misconfigured, or simply newer must not be able to talk the
	// agent into opening a port its operator never named.
	allowed map[portspec.Spec]bool
}

// New builds an Agent.
func New(cfg Config) (*Agent, error) {
	if cfg.Server == "" {
		return nil, errors.New("agent: no server address")
	}
	if err := cfg.ACME.validate(cfg.ServeDir); err != nil {
		return nil, err
	}
	if cfg.ServeDir != "" {
		info, err := os.Stat(cfg.ServeDir)
		if err != nil {
			return nil, fmt.Errorf("agent: cannot serve %s: %w", cfg.ServeDir, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("agent: %s is not a directory", cfg.ServeDir)
		}
		// The served ports are published whether or not the operator listed
		// them, because a directory served on a port nobody can reach is not a
		// configuration anyone wants. With a certificate that is 80 and 443:
		// issuance needs both, and a request against a port the server never
		// bound fails looking like a CA problem rather than a config one.
		served := []portspec.Spec{{Port: cfg.ServePort, Proto: portspec.TCP}}
		if cfg.ACME.enabled() {
			served = ACMEPorts
		} else if cfg.ServePort == 0 {
			return nil, errors.New("agent: serving a directory needs a port")
		}
		for _, spec := range served {
			if !slices.Contains(cfg.Ports, spec) {
				cfg.Ports = append(cfg.Ports, spec)
			}
		}
	}
	if len(cfg.Ports) == 0 {
		return nil, errors.New("agent: no ports declared")
	}
	target := cfg.Target
	if target == "" {
		target = "127.0.0.1"
	}
	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	udpIdle := cfg.UDPIdleTimeout
	if udpIdle == 0 {
		udpIdle = 90 * time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	allowed := make(map[portspec.Spec]bool, len(cfg.Ports))
	for _, spec := range cfg.Ports {
		allowed[spec] = true
	}
	return &Agent{cfg: cfg, target: target, timeout: timeout, udpIdle: udpIdle, log: log, allowed: allowed}, nil
}

// ErrRejected reports that the server refused the session for a stated reason.
// It is distinguished from a transport failure because the answers differ: a
// transport failure is worth retrying and a rejection is not.
type ErrRejected struct{ Reason string }

func (e *ErrRejected) Error() string { return "server rejected the session: " + e.Reason }

// Run connects once and serves until the session ends. The caller decides
// whether to reconnect; Run does not loop, so a rejection is not retried by
// accident.
func (a *Agent) Run(ctx context.Context, sess transport.Session) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer sess.CloseWithError("agent closing")

	control, err := sess.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("opening control stream: %w", err)
	}
	if err := proto.WriteStreamKind(control, proto.KindControl); err != nil {
		return fmt.Errorf("announcing control stream: %w", err)
	}
	udpStream, err := sess.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("opening UDP stream: %w", err)
	}
	if err := proto.WriteStreamKind(udpStream, proto.KindUDP); err != nil {
		return fmt.Errorf("announcing UDP stream: %w", err)
	}

	ctl := proto.NewControlConn(control)
	if err := ctl.Send(proto.Control{Hello: &proto.Hello{
		Version:      proto.Version,
		Token:        a.cfg.Token,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Ports:        a.cfg.Ports,
		Domain:       a.cfg.ACME.Domain,
		WantHostname: a.cfg.ACME.UseServerHostname,
	}}); err != nil {
		return fmt.Errorf("sending hello: %w", err)
	}

	lease, err := awaitLease(ctl)
	if err != nil {
		return err
	}
	published := []any{
		"ip", strings.Join(leaseAddrs(lease), ","),
		"ports", portspec.Format(lease.Bound),
		"target", a.target,
	}
	// The hostname is the whole point of a server that mints subdomains, and it
	// reaches the operator ONLY here. It used to be logged on the certificate
	// path alone, so an agent without one was told its addresses and never the
	// name it had just been given.
	if lease.Hostname != "" {
		published = append(published, "hostname", lease.Hostname)
	}
	a.log.Info("published", published...)
	for _, r := range lease.Refused {
		a.log.Warn("port not published", "port", r.Spec.String(), "reason", r.Reason)
	}

	if err := a.startFileServer(lease); err != nil {
		return err
	}

	conduit := tunnel.NewConduit(sess, udpStream)
	locals := &udpLocals{idle: a.udpIdle}
	defer locals.closeAll()

	var wg sync.WaitGroup
	wg.Go(func() {
		defer cancel()
		conduit.Run(ctx)
	})
	wg.Go(func() {
		defer cancel()
		a.pumpServerPackets(ctx, conduit, locals)
	})
	wg.Go(func() {
		defer cancel()
		a.acceptStreams(ctx, sess)
	})
	// The read deadline in startReader retires a flow whose local service went
	// quiet; this retires one whose remote client did, which nothing else
	// notices because a silent client produces no event at all.
	wg.Go(func() { locals.sweepIdle(ctx) })
	if a.files != nil {
		wg.Go(func() { a.files.start(ctx) })
	}

	err = a.runControl(ctx, ctl)
	cancel()
	conduit.Close()
	wg.Wait()
	return err
}

// awaitLease reads control messages until the server grants a lease or refuses.
func awaitLease(ctl *proto.ControlConn) (*proto.Lease, error) {
	for {
		msg, err := ctl.Recv()
		if err != nil {
			return nil, fmt.Errorf("waiting for lease: %w", err)
		}
		switch {
		case msg.Error != nil:
			return nil, &ErrRejected{Reason: msg.Error.Message}
		case msg.Lease != nil:
			return msg.Lease, nil
		}
	}
}

// runControl answers the server's keepalives and notices it going away.
func (a *Agent) runControl(ctx context.Context, ctl *proto.ControlConn) error {
	recvErr := make(chan error, 1)
	msgs := make(chan proto.Control)
	go func() {
		for {
			msg, err := ctl.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			return err
		case msg := <-msgs:
			switch {
			case msg.Ping:
				if err := ctl.Send(proto.Control{Pong: true}); err != nil {
					return err
				}
			case msg.Error != nil:
				return &ErrRejected{Reason: msg.Error.Message}
			}
		}
	}
}

// acceptStreams serves the tunneled TCP connections the server opens.
func (a *Agent) acceptStreams(ctx context.Context, sess transport.Session) {
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		go a.serveStream(stream)
	}
}

// serveStream dials the local port a tunneled connection asked for.
func (a *Agent) serveStream(stream transport.Stream) {
	// The header must arrive promptly; a stream that opens and then says
	// nothing would otherwise hold a goroutine indefinitely.
	stream.SetDeadline(time.Now().Add(20 * time.Second))

	kind, err := proto.ReadStreamKind(stream)
	if err != nil || kind != proto.KindTCP {
		stream.Close()
		return
	}
	open, err := proto.ReadTCPOpen(stream)
	if err != nil {
		stream.Close()
		return
	}

	if !a.allowed[portspec.Spec{Port: open.Port, Proto: portspec.TCP}] {
		a.log.Warn("refusing an undeclared port", "port", open.Port, "src", open.Src)
		proto.WriteOpenResult(stream, proto.OpenNotAllow)
		stream.Close()
		return
	}

	// A served directory has no local socket to dial: the stream becomes the
	// HTTP connection itself.
	if a.files != nil && a.files.serves(open.Port) {
		if err := proto.WriteOpenResult(stream, proto.OpenOK); err != nil {
			stream.Close()
			return
		}
		a.files.handle(stream, open.Port, open.Src)
		return
	}

	local, err := net.DialTimeout("tcp", a.localAddr(open.Port), a.timeout)
	if err != nil {
		proto.WriteOpenResult(stream, proto.OpenRefused)
		stream.Close()
		return
	}
	if err := proto.WriteOpenResult(stream, proto.OpenOK); err != nil {
		local.Close()
		stream.Close()
		return
	}
	stream.SetDeadline(time.Time{})
	tunnel.Splice(stream, local)
}

// pumpServerPackets delivers tunneled UDP packets to local sockets.
func (a *Agent) pumpServerPackets(ctx context.Context, conduit *tunnel.Conduit, locals *udpLocals) {
	for {
		frame, err := conduit.Recv(ctx)
		if err != nil {
			return
		}
		flowID, port, payload, err := proto.ParseUDPFrame(frame)
		if err != nil {
			continue
		}
		if !a.allowed[portspec.Spec{Port: port, Proto: portspec.UDP}] {
			a.log.Warn("refusing an undeclared UDP port", "port", port)
			continue
		}
		conn, err := locals.get(flowID, port, func() (*net.UDPConn, error) {
			return a.dialLocalUDP(port)
		})
		if err != nil {
			a.log.Debug("could not reach a local UDP port", "port", port, "err", err)
			continue
		}
		// The payload aliases the frame buffer, which is not reused here, so
		// writing it directly is safe.
		if _, err := conn.Write(payload); err != nil {
			locals.drop(flowID)
			continue
		}
		// One reply reader per flow, started on first use, sends whatever the
		// local service answers back under the same flow id.
		locals.startReader(flowID, port, conduit, a.log)
	}
}

// dialLocalUDP connects a socket to the local port, so replies from anywhere
// else are rejected by the kernel rather than forwarded to the client.
func (a *Agent) dialLocalUDP(port uint16) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", a.localAddr(port))
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

// localAddr renders the local address for a published port.
func (a *Agent) localAddr(port uint16) string {
	return net.JoinHostPort(a.target, strconv.Itoa(int(port)))
}
