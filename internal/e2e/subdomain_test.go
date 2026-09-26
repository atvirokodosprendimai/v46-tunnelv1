package e2e

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/agent"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/dnsd"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/pool"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/server"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/subdomain"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tlsutil"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/quictp"
)

const e2eZone = "tun.example.test"

// The whole point of the built-in nameserver: an agent connects, is given a
// random subdomain, and that name resolves — through a real DNS query to a real
// nameserver — to the address its traffic actually arrives on.
//
// The unit tests cover the registry and the nameserver separately. Neither can
// tell whether the server binds a label to the SAME addresses it published the
// agent on, which is the claim that matters and the one only this test makes.
func TestSubdomainResolvesToThePublishedAddress(t *testing.T) {
	requireIPv6Loopback(t)

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	registry := subdomain.NewRegistry(e2eZone)
	dnsAddr := startNameserver(t, registry, quiet)

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
		Domain:    e2eZone,
		Registry:  registry,
		Keepalive: time.Second,
		Logger:    quiet,
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

	// Wait for the tunnel, then find the label the server minted. Going through
	// the registry rather than parsing a log keeps the test about behaviour.
	dialPublished(t, port).Close()
	label := soleLabel(t, registry)

	fqdn := label + "." + e2eZone
	resp := dnsQuery(t, dnsAddr, fqdn, dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("resolving %s: rcode=%s answers=%d", fqdn, dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	resolved := resp.Answer[0].(*dns.AAAA).AAAA.String()
	if resolved != "::1" {
		t.Fatalf("%s resolved to %s, want the leased address ::1", fqdn, resolved)
	}

	// And the resolved address actually carries the tunnel. Resolving to the
	// right string is not the same as the address serving the agent, and it is
	// the second half that the system promises.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(resolved, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		t.Fatalf("dialing the resolved address: %v", err)
	}
	defer conn.Close()

	want := "reached via " + fqdn
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("writing: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != want {
		t.Errorf("echoed %q, want %q", got, want)
	}

	// When the session ends the name must stop resolving, rather than pointing
	// at an address that may shortly belong to a different agent.
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if dnsQuery(t, dnsAddr, fqdn, dns.TypeAAAA).Rcode == dns.RcodeNameError {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Error("the subdomain still resolved after the session ended")
}

// Two agents must get different labels, each resolving to its own lease.
func TestEachAgentGetsItsOwnSubdomain(t *testing.T) {
	registry := subdomain.NewRegistry(e2eZone)

	first, err := registry.Bind("alice", nil)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	second, err := registry.Bind("bob", nil)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if first.Label == second.Label {
		t.Fatal("two agents were given the same label")
	}
	if len(first.Label) != subdomain.Length {
		t.Errorf("label %q is %d characters, want %d", first.Label, len(first.Label), subdomain.Length)
	}
	if strings.Contains(first.FQDN(e2eZone), "alice") {
		t.Errorf("the label leaks the agent's identity: %s", first.FQDN(e2eZone))
	}
}

// startNameserver runs the authoritative server on a free loopback port.
func startNameserver(t *testing.T, registry *subdomain.Registry, log *slog.Logger) string {
	t.Helper()

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a DNS port: %v", err)
	}
	addr := probe.LocalAddr().String()
	probe.Close()

	srv, err := dnsd.New(dnsd.Config{
		Registry:         registry,
		Nameservers:      []string{"ns1." + e2eZone},
		QueriesPerSecond: 1000,
		Logger:           log,
	})
	if err != nil {
		t.Fatalf("dnsd.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.ListenAndServe(ctx, addr)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(e2eZone), dns.TypeSOA)
		if _, _, err := (&dns.Client{Timeout: time.Second}).Exchange(m, addr); err == nil {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nameserver never came up on %s", addr)
	return ""
}

func dnsQuery(t *testing.T, server, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, server)
	if err != nil {
		t.Fatalf("querying %s: %v", name, err)
	}
	return resp
}

// soleLabel waits for exactly one binding and returns its label.
func soleLabel(t *testing.T, registry *subdomain.Registry) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if bindings := registry.Bindings(); len(bindings) == 1 {
			return bindings[0].Label
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("no subdomain was bound for the connected agent")
	return ""
}
