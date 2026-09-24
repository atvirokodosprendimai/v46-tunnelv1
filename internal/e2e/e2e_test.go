// Package e2e drives a real server and a real agent against each other over a
// real QUIC session.
//
// The unit tests cover parsing and bookkeeping; none of them can tell whether a
// connection to a published port actually reaches the agent's local service.
// That is the claim the whole system makes, and only this test checks it.
//
// The loopback trick: the pool leases ::1 while the agent dials 127.0.0.1, so
// both ends can use the SAME port number on one machine without the server's
// own listener swallowing the agent's dial.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/agent"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/pool"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/server"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tlsutil"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/quictp"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/wstp"
)

// leaseIP is the single address in the test pool. It is the IPv6 loopback so
// that the published side and the agent's local side never collide.
const leaseIP = "::1"

func init() {
	// Keep the packages' own logging out of the test output.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// harness is a running server with a transport dialer pointed at it.
type harness struct {
	addr   string
	dialer transport.Dialer
}

// startServer brings up a tunnel server reached over QUIC.
func startServer(t *testing.T, denyPorts []uint16) *harness {
	t.Helper()
	return startServerOn(t, denyPorts, "quic")
}

// startServerOn brings up a tunnel server on the loopback with a one-address
// pool, reached over the named transport.
func startServerOn(t *testing.T, denyPorts []uint16, kind string) *harness {
	t.Helper()
	requireIPv6Loopback(t)

	tlsConf, fingerprint, err := tlsutil.SelfSigned([]string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	addrPool, err := pool.New([]string{leaseIP}, pool.Sticky)
	if err != nil {
		t.Fatalf("pool.New: %v", err)
	}
	srv, err := server.New(server.Config{
		Pool:      addrPool,
		Auth:      server.StaticTokens{"test-token": "testagent"},
		DenyPorts: denyPorts,
		Keepalive: time.Second,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	clientTLS, err := tlsutil.ClientConfig("localhost", fingerprint, false)
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	switch kind {
	case "quic":
		ln, err := quictp.Listen("127.0.0.1:0", tlsConf)
		if err != nil {
			t.Fatalf("quictp.Listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
		go srv.Serve(ctx, ln)
		return &harness{addr: ln.Addr().String(), dialer: quictp.Dialer{TLSConfig: clientTLS}}

	case "wss":
		tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listening for WSS: %v", err)
		}
		handler := wstp.NewHandler(tcpLn.Addr())
		mux := http.NewServeMux()
		mux.Handle(wstp.Path, handler)
		httpSrv := &http.Server{Handler: mux, TLSConfig: tlsConf.Clone()}
		t.Cleanup(func() { httpSrv.Close() })
		go httpSrv.ServeTLS(tcpLn, "", "")
		go srv.Serve(ctx, handler)
		return &harness{addr: tcpLn.Addr().String(), dialer: wstp.Dialer{TLSConfig: clientTLS}}

	default:
		t.Fatalf("unknown transport %q", kind)
		return nil
	}
}

// TestFallbackTransportCarriesBothProtocols covers the WebSocket transport,
// which shares no transport code with QUIC and is the only path that exercises
// UDP-over-stream: yamux advertises no datagrams, so every tunneled packet
// takes the conduit's fallback branch rather than the one the other tests run.
func TestFallbackTransportCarriesBothProtocols(t *testing.T) {
	h := startServerOn(t, nil, "wss")

	tcpLocal, tcpPort := freeTCPListener(t)
	defer tcpLocal.Close()
	go echoTCP(tcpLocal)

	udpLocal, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer udpLocal.Close()
	udpPort := uint16(udpLocal.LocalAddr().(*net.UDPAddr).Port)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udpLocal.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpLocal.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()

	h.connect(t, agent.Config{Ports: []portspec.Spec{
		{Port: tcpPort, Proto: portspec.TCP},
		{Port: udpPort, Proto: portspec.UDP},
	}})

	conn := dialPublished(t, tcpPort)
	defer conn.Close()
	if _, err := conn.Write([]byte("over wss")); err != nil {
		t.Fatalf("writing through the fallback: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len("over wss"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading through the fallback: %v", err)
	}
	if string(got) != "over wss" {
		t.Errorf("echoed %q, want %q", got, "over wss")
	}

	remote, err := net.ResolveUDPAddr("udp", published(udpPort))
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	client, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer client.Close()

	deadline := time.Now().Add(15 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Fatalf("writing a packet: %v", err)
		}
		client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := client.Read(buf)
		if err != nil {
			continue
		}
		if got := string(buf[:n]); got != "echo:ping" {
			t.Fatalf("received %q, want %q", got, "echo:ping")
		}
		return
	}
	t.Fatal("no UDP reply came back over the fallback transport within 15s")
}

// connect runs an agent against the harness for the test's lifetime.
func (h *harness) connect(t *testing.T, cfg agent.Config) {
	t.Helper()
	cfg.Server = h.addr
	if cfg.Token == "" {
		cfg.Token = "test-token"
	}
	if cfg.Target == "" {
		cfg.Target = "127.0.0.1"
	}

	ag, err := agent.New(cfg)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sess, err := h.dialer.Dial(ctx, h.addr)
	if err != nil {
		t.Fatalf("dialing the server: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- ag.Run(ctx, sess) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop within 5s of its context being cancelled")
		}
	})
}

// freeTCPListener returns a listener on the loopback and the port it holds, so
// a test can serve on exactly that port.
func freeTCPListener(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a local port: %v", err)
	}
	return ln, uint16(ln.Addr().(*net.TCPAddr).Port)
}

// echoTCP answers every connection with what it was sent.
func echoTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			io.Copy(c, c)
		}()
	}
}

// published renders the address a port is published on.
func published(port uint16) string { return net.JoinHostPort(leaseIP, fmt.Sprint(port)) }

// dialPublished retries until the tunnel is up, because the lease is granted
// asynchronously and a test that raced it would be flaky rather than wrong.
func dialPublished(t *testing.T, port uint16) net.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", published(port), time.Second)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("published port %d never became reachable: %v", port, lastErr)
	return nil
}

// TestTCPReachesTheAgentsLocalPort is the system's central claim: a connection
// to :N on the leased address becomes a connection to :N on the agent's host.
func TestTCPReachesTheAgentsLocalPort(t *testing.T) {
	h := startServer(t, nil)

	local, port := freeTCPListener(t)
	defer local.Close()
	go echoTCP(local)

	h.connect(t, agent.Config{Ports: []portspec.Spec{{Port: port, Proto: portspec.TCP}}})

	conn := dialPublished(t, port)
	defer conn.Close()

	want := "the payload that proves the path"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("writing through the tunnel: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading through the tunnel: %v", err)
	}
	if string(got) != want {
		t.Errorf("echoed %q, want %q", got, want)
	}
}

// TestUDPReachesTheAgentsLocalPort covers the datagram path, which shares none
// of the TCP path's code: a different frame, a flow table, and a reply that has
// to find its way back to the right client.
func TestUDPReachesTheAgentsLocalPort(t *testing.T) {
	h := startServer(t, nil)

	localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer localConn.Close()
	port := uint16(localConn.LocalAddr().(*net.UDPAddr).Port)

	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := localConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			localConn.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()

	h.connect(t, agent.Config{Ports: []portspec.Spec{{Port: port, Proto: portspec.UDP}}})

	remote, err := net.ResolveUDPAddr("udp", published(port))
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	client, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer client.Close()

	// UDP is lossy and the tunnel has to come up first, so the packet is
	// retried rather than sent once and asserted on.
	deadline := time.Now().Add(10 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Fatalf("writing a packet: %v", err)
		}
		client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := client.Read(buf)
		if err != nil {
			continue
		}
		if got := string(buf[:n]); got != "echo:ping" {
			t.Fatalf("received %q, want %q", got, "echo:ping")
		}
		return
	}
	t.Fatal("no UDP reply came back through the tunnel within 10s")
}

// TestServedDirectoryIsReachable covers --dir, which takes a different path
// through the agent: no local socket is dialled at all, the tunneled stream
// becomes the HTTP connection.
func TestServedDirectoryIsReachable(t *testing.T) {
	h := startServer(t, nil)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("downloadable"), 0o644); err != nil {
		t.Fatalf("writing a file to serve: %v", err)
	}

	reserved, port := freeTCPListener(t)
	// Release the port: nothing local should be listening on it, because the
	// point of serving off the stream is that there is no local socket.
	reserved.Close()

	h.connect(t, agent.Config{ServeDir: dir, ServePort: port})

	if body := getPublished(t, port, "/notes.txt"); body != "downloadable" {
		t.Errorf("file body = %q, want %q", body, "downloadable")
	}
}

// TestServedDirectoryPrefersIndexHTML pins the requested behaviour: index.html
// is shown when it exists, and a listing when it does not.
func TestServedDirectoryPrefersIndexHTML(t *testing.T) {
	h := startServer(t, nil)

	dir := t.TempDir()
	sub := filepath.Join(dir, "listed")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("making a subdirectory: %v", err)
	}
	for path, content := range map[string]string{
		filepath.Join(dir, "index.html"): "<h1>the index</h1>",
		filepath.Join(sub, "inside.txt"): "y",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}

	reserved, port := freeTCPListener(t)
	reserved.Close()
	h.connect(t, agent.Config{ServeDir: dir, ServePort: port})

	if body := getPublished(t, port, "/"); !strings.Contains(body, "the index") {
		t.Errorf("root served %q, want the contents of index.html", body)
	}
	// The subdirectory has no index.html, so it falls back to a listing — and
	// the listing has to actually name the file, not merely return 200.
	if listing := getPublished(t, port, "/listed/"); !strings.Contains(listing, "inside.txt") {
		t.Errorf("directory listing = %q, want it to name inside.txt", listing)
	}
}

// getPublished fetches a path from a published HTTP port, retrying until the
// tunnel is up.
func getPublished(t *testing.T, port uint16, path string) string {
	t.Helper()
	url := "http://" + published(port) + path
	client := &http.Client{Timeout: 5 * time.Second}

	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(25 * time.Millisecond)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("reading %s: %v", url, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 (body %q)", url, resp.StatusCode, body)
		}
		return string(body)
	}
	t.Fatalf("GET %s never succeeded: %v", url, lastErr)
	return ""
}

// TestMailPortIsRefusedButTheLeaseSurvives pins the decision taken for the deny
// list: one denied port costs the agent that port, never its whole tunnel.
func TestMailPortIsRefusedButTheLeaseSurvives(t *testing.T) {
	h := startServer(t, nil)

	local, port := freeTCPListener(t)
	defer local.Close()
	go echoTCP(local)

	h.connect(t, agent.Config{Ports: []portspec.Spec{
		{Port: 25, Proto: portspec.TCP}, // on the default deny list
		{Port: port, Proto: portspec.TCP},
	}})

	// The good port still works, which is the half that a "reject the whole
	// lease" policy would have failed.
	dialPublished(t, port).Close()

	// And the denied one is not listening. On its own that assertion would also
	// pass with the whole tunnel down, so it is made only after the port above
	// has proved the session is live.
	if c, err := net.DialTimeout("tcp", published(25), 500*time.Millisecond); err == nil {
		c.Close()
		t.Error("port 25 accepted a connection; the mail block did not take effect")
	}
}

// TestUnknownTokenIsRejectedWithAReason pins that a refusal arrives as a
// message. Dropping the connection instead would be indistinguishable from a
// network failure, and an agent retries those forever.
func TestUnknownTokenIsRejectedWithAReason(t *testing.T) {
	h := startServer(t, nil)

	ag, err := agent.New(agent.Config{
		Server: h.addr,
		Token:  "not-a-real-token",
		Ports:  []portspec.Spec{{Port: 9999, Proto: portspec.TCP}},
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sess, err := h.dialer.Dial(ctx, h.addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	var rejected *agent.ErrRejected
	if err := ag.Run(ctx, sess); !errors.As(err, &rejected) {
		t.Fatalf("Run returned %v, want an *agent.ErrRejected", err)
	}
	if !strings.Contains(rejected.Reason, "token") {
		t.Errorf("rejection reason = %q, want it to mention the token", rejected.Reason)
	}
}

// requireIPv6Loopback skips when ::1 is unavailable, which is the one
// environment assumption these tests make.
func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable here: %v", err)
	}
	ln.Close()
}
