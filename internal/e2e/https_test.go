package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/agent"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/pool"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/server"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/subdomain"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tlsutil"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/quictp"
)

// testCerts is a CertificateSource backed by a certificate minted in the test.
//
// The real source drives an ACME order, which needs a CA. Substituting one here
// is what makes the TERMINATION path testable at all: what is under test is
// that the server decrypts and forwards to the agent's backend port, and that
// is independent of where the certificate came from.
type testCerts struct {
	cert  *tls.Certificate
	ready bool
}

func (c *testCerts) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.cert, nil
}

func (c *testCerts) Ready() bool { return c.ready }

// wildcardCerts mints a self-signed wildcard for the test zone.
func wildcardCerts(t *testing.T) (*testCerts, *x509.CertPool) {
	t.Helper()
	conf, _, err := tlsutil.SelfSigned([]string{"*." + e2eZone, e2eZone})
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(conf.Certificates[0].Leaf)
	return &testCerts{cert: &conf.Certificates[0], ready: true}, roots
}

// httpsHarness brings up a server with a domain and a certificate source.
func httpsHarness(t *testing.T, certs server.CertificateSource, httpsPort uint16) (*harness, *subdomain.Registry) {
	t.Helper()
	requireIPv6Loopback(t)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	registry := subdomain.NewRegistry(e2eZone)
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
		Certs:     certs,
		HTTPSPort: httpsPort,
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
	return &harness{addr: ln.Addr().String(), dialer: quictp.Dialer{TLSConfig: clientTLS}}, registry
}

// The claim: an HTTPS request to the agent's subdomain is decrypted by the
// server and reaches the agent's cleartext local service.
//
// Termination is bound on an unprivileged port here. 443 is the default and
// needs root, so testing on it would mean skipping — and a skipped test of the
// one path that distinguishes this feature is not a tested path at all.
func TestTerminatedHTTPSReachesTheAgentBackend(t *testing.T) {
	certs, roots := wildcardCerts(t)

	reserved, httpsPort := freeTCPListener(t)
	reserved.Close()
	h, registry := httpsHarness(t, certs, httpsPort)

	// A cleartext HTTP service on the agent's machine — what a real backend is.
	backend, backendPort := freeTCPListener(t)
	defer backend.Close()
	go http.Serve(backend, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plaintext from the agent, host="+r.Host)
	}))

	lease := h.connectLease(t, agent.Config{
		Ports:        []portspec.Spec{{Port: backendPort, Proto: portspec.TCP}},
		HTTPSBackend: backendPort,
	})
	if !lease.HTTPS {
		t.Fatalf("the server did not terminate TLS; refusals: %+v", lease.Refused)
	}

	label := soleLabel(t, registry)
	fqdn := label + "." + e2eZone

	conn, err := tls.Dial("tcp", net.JoinHostPort(leaseIP, strconv.Itoa(int(httpsPort))), &tls.Config{
		ServerName: fqdn,
		RootCAs:    roots,
	})
	if err != nil {
		t.Fatalf("TLS handshake against the terminated listener: %v", err)
	}
	defer conn.Close()

	// The handshake alone proves the wildcard matched the random subdomain,
	// which is the thing a per-agent certificate would have had to be issued
	// for. Verifying it explicitly, because a misconfigured RootCAs would make
	// the dial succeed for the wrong reason.
	if got := conn.ConnectionState().ServerName; got != fqdn {
		t.Errorf("negotiated server name = %q, want %q", got, fqdn)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+fqdn+"/", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	resp, err := readResponse(conn, req)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "plaintext from the agent") {
		t.Errorf("body = %q, want the agent's cleartext backend", body)
	}
	// The Host the backend saw is the subdomain, so a vhost-based local service
	// routes correctly rather than seeing the tunnel's own address.
	if !strings.Contains(string(body), "host="+fqdn) {
		t.Errorf("backend saw %q, want Host=%s", body, fqdn)
	}
}

// An agent that declares 443 itself AND asks the server to terminate is
// refused the termination, not the lease: the two mean opposite things for the
// same listener and silently picking either is wrong for one of them.
func TestDeclaring443AndAskingForTerminationIsRefused(t *testing.T) {
	certs, _ := wildcardCerts(t)
	reserved, httpsPort := freeTCPListener(t)
	reserved.Close()
	h, _ := httpsHarness(t, certs, httpsPort)

	local, port := freeTCPListener(t)
	defer local.Close()
	go echoTCP(local)

	lease := h.connectLease(t, agent.Config{
		Ports: []portspec.Spec{
			{Port: port, Proto: portspec.TCP},
			{Port: httpsPort, Proto: portspec.TCP},
		},
		HTTPSBackend: port,
	})
	if lease.HTTPS {
		t.Error("the server terminated TLS for an agent that also declared 443 itself")
	}
	if !refusedPort(lease, httpsPort) {
		t.Error("the conflict was not reported as a refusal against 443")
	}
	// The rest of the lease survives, which is the half a whole-lease refusal
	// would have lost.
	if len(lease.Bound) == 0 {
		t.Error("the conflict cost the agent its entire lease")
	}
}

// Asking a server with no certificate must cost the agent 443 and nothing else.
func TestTerminationWithoutACertificateIsRefused(t *testing.T) {
	reserved, httpsPort := freeTCPListener(t)
	reserved.Close()
	h, _ := httpsHarness(t, nil, httpsPort)

	local, port := freeTCPListener(t)
	defer local.Close()
	go echoTCP(local)

	lease := h.connectLease(t, agent.Config{
		Ports:        []portspec.Spec{{Port: port, Proto: portspec.TCP}},
		HTTPSBackend: port,
	})
	if lease.HTTPS {
		t.Error("the server claimed to terminate TLS with no certificate configured")
	}
	if !refusedPort(lease, httpsPort) {
		t.Error("no refusal was reported for the unavailable termination")
	}
	if len(lease.Bound) != 1 {
		t.Errorf("bound %d ports, want the declared one to survive", len(lease.Bound))
	}
}

// A certificate that is configured but not yet issued must also refuse rather
// than binding a listener that cannot complete a handshake.
func TestTerminationWaitsForTheCertificate(t *testing.T) {
	certs, _ := wildcardCerts(t)
	certs.ready = false
	reserved, httpsPort := freeTCPListener(t)
	reserved.Close()
	h, _ := httpsHarness(t, certs, httpsPort)

	local, port := freeTCPListener(t)
	defer local.Close()
	go echoTCP(local)

	lease := h.connectLease(t, agent.Config{
		Ports:        []portspec.Spec{{Port: port, Proto: portspec.TCP}},
		HTTPSBackend: port,
	})
	if lease.HTTPS {
		t.Error("the server terminated TLS before the certificate was ready")
	}
}

// readResponse parses an HTTP response off a raw connection.
func readResponse(conn net.Conn, req *http.Request) (*http.Response, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	return http.ReadResponse(bufio.NewReader(conn), req)
}

func refusedPort(lease *proto.Lease, port uint16) bool {
	for _, r := range lease.Refused {
		if r.Spec.Port == port {
			return true
		}
	}
	return false
}
