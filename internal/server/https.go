package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
)

// DefaultHTTPSPort is the port the server terminates TLS on for an agent's
// subdomain unless the operator names another.
//
// It is configurable because 443 is privileged: a deployment behind a load
// balancer terminates on a high port, and so does anything that has to run
// unprivileged. Without the knob the whole termination path is only reachable
// as root, including from a test.
const DefaultHTTPSPort = 443

// setUpHTTPS decides whether to terminate TLS for this agent and does it.
//
// Every refusal here costs the agent port 443 alone and never its lease: an
// agent that also declared 443 itself, or asked a server with no certificate,
// still gets every other port it named.
func (s *Server) setUpHTTPS(ctx context.Context, pub *publication, hello *proto.Hello, hostname string, declared []portspec.Spec) (bool, []proto.Refusal) {
	if hello.HTTPSBackend == 0 {
		return false, nil
	}
	spec := httpsSpec(s.httpsPort)

	refuse := func(reason string) (bool, []proto.Refusal) {
		pub.log.Info("not terminating TLS for this agent", "reason", reason)
		return false, []proto.Refusal{{Spec: spec, Reason: reason}}
	}

	switch {
	case hostname == "":
		return refuse("the server serves no domain, so there is no hostname to terminate TLS for")
	case s.certs == nil:
		return refuse("the server has no wildcard certificate configured")
	case !s.certs.Ready():
		// Issuance may still be in flight, or may have failed. Either way the
		// handshake would fail, and saying so now is better than a listener
		// that accepts and then cannot answer.
		return refuse("the wildcard certificate is not available yet")
	}
	for _, d := range declared {
		if d.Port == s.httpsPort && d.Proto == portspec.TCP {
			// Both want the same listener, and they mean opposite things: one
			// forwards raw bytes, the other decrypts first. Silently picking
			// either would be wrong for the agent that asked for the other.
			return refuse("this agent also declared 443/tcp; drop it to have the server terminate TLS, or drop --https-backend to forward raw bytes")
		}
	}

	if refusals := pub.bindHTTPS(ctx, s.httpsPort, hello.HTTPSBackend, s.certs); len(refusals) > 0 {
		return false, refusals
	}
	pub.log.Info("terminating TLS", "hostname", hostname, "backend_port", hello.HTTPSBackend)
	return true, nil
}

// bindHTTPS binds 443 on every leased address with the wildcard certificate and
// forwards each decrypted stream to the agent's chosen local port.
//
// This is the one path where the tunnel stops being a raw byte pipe. Everywhere
// else the server moves opaque bytes and cannot read them; here it holds the
// key and decrypts, so it sees the plaintext of every request. That is inherent
// to terminating at the server rather than at the agent, and it is why this is
// requested per agent rather than applied to 443 for everyone.
func (p *publication) bindHTTPS(ctx context.Context, port, backend uint16, certs CertificateSource) []proto.Refusal {
	tlsConf := &tls.Config{
		GetCertificate: certs.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
	}

	spec := httpsSpec(port)
	var lastErr error
	bound := false
	for _, addr := range p.addrs {
		if err := p.bindHTTPSOne(ctx, addr, port, backend, tlsConf); err != nil {
			lastErr = err
			continue
		}
		bound = true
	}
	if !bound {
		return []proto.Refusal{{Spec: spec, Reason: bindReason(lastErr)}}
	}

	p.mu.Lock()
	p.bound = append(p.bound, spec)
	p.mu.Unlock()
	return nil
}

// bindHTTPSOne opens one TLS listener on one address.
func (p *publication) bindHTTPSOne(ctx context.Context, addr netip.Addr, port, backend uint16, tlsConf *tls.Config) error {
	hostPort := net.JoinHostPort(addr.String(), fmt.Sprint(port))
	raw, err := net.Listen("tcp", hostPort)
	if err != nil {
		return err
	}
	ln := tls.NewListener(raw, tlsConf)

	p.mu.Lock()
	p.listeners = append(p.listeners, ln)
	p.mu.Unlock()

	// The accepted connection is already decrypted, so it is forwarded exactly
	// like any other TCP stream — but addressed to the agent's backend port
	// rather than to 443, because the agent's local service speaks cleartext.
	go p.acceptTCP(ctx, ln, backend)
	return nil
}

// httpsSpec is the published port reported in the lease for the terminated
// HTTPS listener.
func httpsSpec(port uint16) portspec.Spec {
	return portspec.Spec{Port: port, Proto: portspec.TCP}
}

// CertificateSource supplies the certificate a TLS handshake is answered with.
//
// It is an interface at the consumer rather than the wildcard manager's
// concrete type so the server does not depend on the ACME machinery — which
// also makes a terminating listener testable with a certificate minted in the
// test, with no CA anywhere.
type CertificateSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Ready() bool
}
