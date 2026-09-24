package e2e

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/agent"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/pool"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/server"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tlsutil"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/quictp"
)

// A dual-stack lease has to publish the SAME port on both families, so one
// hostname with an A and an AAAA record reaches the same service either way.
//
// Both loopbacks are used as the pool. The agent's local target is a third
// address — the IPv4 loopback on a port the server does not bind — so neither
// published listener can be mistaken for the local service.
func TestDualStackPublishesOnBothFamilies(t *testing.T) {
	requireIPv6Loopback(t)

	tlsConf, fingerprint, err := tlsutil.SelfSigned([]string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	// 127.0.0.1 and ::1 are the only two addresses bindable on an unconfigured
	// host, so they are the pool; the agent dials a port on 127.0.0.1 that the
	// server never binds, which keeps the two roles separate.
	addrPool, err := pool.New([]string{"127.0.0.1", leaseIP}, pool.Sticky)
	if err != nil {
		t.Fatalf("pool.New: %v", err)
	}
	if len(addrPool.Families()) != 2 {
		t.Fatalf("pool holds %v, want both families", addrPool.Families())
	}
	srv, err := server.New(server.Config{
		Pool:      addrPool,
		Auth:      server.StaticTokens{"test-token": "testagent"},
		Keepalive: time.Second,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ln, err := quictp.Listen("127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("quictp.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)

	clientTLS, err := tlsutil.ClientConfig("localhost", fingerprint, false)
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	h := &harness{addr: ln.Addr().String(), dialer: quictp.Dialer{TLSConfig: clientTLS}}

	local, port := freeTCPListener(t)
	defer local.Close()
	go echoTCP(local)

	h.connect(t, agent.Config{Ports: []portspec.Spec{{Port: port, Proto: portspec.TCP}}})

	// The same port must answer on both families and reach the same echo
	// service. Checking only one would pass on a server that bound one address
	// and silently dropped the other, which is exactly the regression here.
	for _, host := range []string{"127.0.0.1", leaseIP} {
		t.Run(host, func(t *testing.T) {
			addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
			conn := dialUntilReady(t, addr)
			defer conn.Close()

			want := "reached over " + host
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
		})
	}
}

// dialUntilReady retries until the tunnel is up, for an arbitrary address.
func dialUntilReady(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s never became reachable: %v", addr, lastErr)
	return nil
}
