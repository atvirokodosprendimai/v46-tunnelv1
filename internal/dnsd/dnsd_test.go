package dnsd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/subdomain"
)

const testZone = "tun.example.com"

// start brings up a real nameserver on a real socket and returns its address.
//
// A fake ResponseWriter would test the handler while skipping the wire, and the
// wire is where a malformed answer actually shows up.
func start(t *testing.T, reg *subdomain.Registry, qps int) (string, *Server) {
	t.Helper()

	// Reserve a port by binding UDP, then release it for the server. A port
	// that is free at this instant is overwhelmingly still free a microsecond
	// later, and the alternative is a hardcoded port that collides in CI.
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := probe.LocalAddr().String()
	probe.Close()

	srv, err := New(Config{
		Registry:         reg,
		Nameservers:      []string{"ns1." + testZone},
		QueriesPerSecond: qps,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.ListenAndServe(ctx, addr)

	// Wait for it to answer rather than sleeping a fixed amount.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := query(addr, testZone, dns.TypeSOA); err == nil {
			return addr, srv
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nameserver never came up on %s", addr)
	return "", nil
}

// query sends one question and returns the reply.
func query(server, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, server)
	return resp, err
}

func mustQuery(t *testing.T, server, name string, qtype uint16) *dns.Msg {
	t.Helper()
	resp, err := query(server, name, qtype)
	if err != nil {
		t.Fatalf("query %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return resp
}

func bindAgent(t *testing.T, reg *subdomain.Registry, agentID string, addrs ...string) subdomain.Binding {
	t.Helper()
	parsed := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		parsed[i] = netip.MustParseAddr(a)
	}
	b, err := reg.Bind(agentID, parsed)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	return b
}

// The central claim: a minted subdomain resolves to the addresses its agent
// holds, and a dual-stack agent answers on both record types.
func TestResolvesAgentAddresses(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)
	b := bindAgent(t, reg, "laptop", "198.51.100.7", "2001:db8::7")

	a := mustQuery(t, addr, b.FQDN(testZone), dns.TypeA)
	if a.Rcode != dns.RcodeSuccess || len(a.Answer) != 1 {
		t.Fatalf("A query: rcode=%s answers=%d", dns.RcodeToString[a.Rcode], len(a.Answer))
	}
	if got := a.Answer[0].(*dns.A).A.String(); got != "198.51.100.7" {
		t.Errorf("A = %s, want 198.51.100.7", got)
	}
	if !a.Authoritative {
		t.Error("answer is not marked authoritative")
	}

	quad := mustQuery(t, addr, b.FQDN(testZone), dns.TypeAAAA)
	if quad.Rcode != dns.RcodeSuccess || len(quad.Answer) != 1 {
		t.Fatalf("AAAA query: rcode=%s answers=%d", dns.RcodeToString[quad.Rcode], len(quad.Answer))
	}
	if got := quad.Answer[0].(*dns.AAAA).AAAA.String(); got != "2001:db8::7" {
		t.Errorf("AAAA = %s, want 2001:db8::7", got)
	}
}

// An agent that holds only IPv6 must answer an A query with NOERROR and no
// records, not NXDOMAIN. NXDOMAIN says the NAME does not exist, which would
// stop a resolver from trying AAAA at all.
func TestSingleFamilyAgentIsNoErrorNotNXDomain(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)
	b := bindAgent(t, reg, "v6only", "2001:db8::9")

	a := mustQuery(t, addr, b.FQDN(testZone), dns.TypeA)
	if a.Rcode != dns.RcodeSuccess {
		t.Errorf("A rcode = %s, want NOERROR; NXDOMAIN would stop the resolver trying AAAA", dns.RcodeToString[a.Rcode])
	}
	if len(a.Answer) != 0 {
		t.Errorf("A answers = %d, want 0", len(a.Answer))
	}
	if len(a.Ns) == 0 {
		t.Error("no SOA in authority, so the negative answer is not cacheable")
	}

	quad := mustQuery(t, addr, b.FQDN(testZone), dns.TypeAAAA)
	if len(quad.Answer) != 1 {
		t.Errorf("AAAA answers = %d, want 1", len(quad.Answer))
	}
}

func TestUnknownLabelIsNXDomain(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)

	resp := mustQuery(t, addr, "nosuchagent."+testZone, dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Ns) == 0 {
		t.Error("no SOA in authority, so the NXDOMAIN is not cacheable")
	}
}

// Releasing must stop the name resolving immediately. A tunnel that has ended
// but whose name still answers sends traffic to an address the agent no longer
// holds — which by then may belong to a different agent.
func TestReleasedLabelStopsResolving(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)
	b := bindAgent(t, reg, "laptop", "198.51.100.7")

	if resp := mustQuery(t, addr, b.FQDN(testZone), dns.TypeA); len(resp.Answer) != 1 {
		t.Fatalf("the name did not resolve before release")
	}
	reg.Release("laptop")
	if resp := mustQuery(t, addr, b.FQDN(testZone), dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode after release = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

// A name outside the zone gets REFUSED, not NXDOMAIN: this server has no
// standing to assert that a name in someone else's zone does not exist.
func TestForeignZoneIsRefused(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)

	resp := mustQuery(t, addr, "www.example.org", dns.TypeA)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if resp.Authoritative {
		t.Error("claimed authority over a zone it does not serve")
	}
}

// Recursion must never be advertised. A nameserver that offers it becomes a
// resolver for the whole internet and an amplification vector.
func TestRecursionIsNeverAvailable(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)
	b := bindAgent(t, reg, "laptop", "198.51.100.7")

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(b.FQDN(testZone)), dns.TypeA)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.RecursionAvailable {
		t.Error("the server advertised recursion")
	}
}

// An ANY query is the most useful shape for amplification, so it is answered
// minimally rather than with every record known (RFC 8482).
func TestAnyQueryIsAnsweredMinimally(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)

	resp := mustQuery(t, addr, testZone, dns.TypeANY)
	if len(resp.Answer) != 1 {
		t.Errorf("ANY at the apex returned %d records, want 1 (minimal)", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.SOA); !ok {
		t.Errorf("ANY returned %T, want the SOA", resp.Answer[0])
	}
}

func TestZoneApex(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)

	soa := mustQuery(t, addr, testZone, dns.TypeSOA)
	if len(soa.Answer) != 1 {
		t.Fatalf("SOA answers = %d, want 1", len(soa.Answer))
	}
	if got := soa.Answer[0].(*dns.SOA).Minttl; got != negativeTTL {
		t.Errorf("SOA minimum = %d, want %d", got, negativeTTL)
	}

	ns := mustQuery(t, addr, testZone, dns.TypeNS)
	if len(ns.Answer) != 1 {
		t.Fatalf("NS answers = %d, want 1", len(ns.Answer))
	}
	if got := ns.Answer[0].(*dns.NS).Ns; got != "ns1."+testZone+"." {
		t.Errorf("NS = %s, want ns1.%s.", got, testZone)
	}
}

// TXT is what answers an ACME DNS-01 challenge from this zone, and it is the
// mechanism the wildcard certificate depends on.
func TestTXTServesChallengeRecords(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)

	name := "_acme-challenge." + testZone
	if resp := mustQuery(t, addr, name, dns.TypeTXT); resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode before publishing = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}

	reg.SetTXT(name, "the-challenge-value")
	resp := mustQuery(t, addr, name, dns.TypeTXT)
	if len(resp.Answer) != 1 {
		t.Fatalf("TXT answers = %d, want 1", len(resp.Answer))
	}
	if got := resp.Answer[0].(*dns.TXT).Txt[0]; got != "the-challenge-value" {
		t.Errorf("TXT = %q, want the challenge value", got)
	}

	reg.ClearTXT(name)
	if resp := mustQuery(t, addr, name, dns.TypeTXT); resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode after clearing = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

// A deeper name must not be answered by trimming it down to a label that does
// exist — "anything.<live-label>.<zone>" is not the agent.
func TestDeeperNamesAreNotMatched(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)
	b := bindAgent(t, reg, "laptop", "198.51.100.7")

	resp := mustQuery(t, addr, "extra."+b.FQDN(testZone), dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN for a deeper name", dns.RcodeToString[resp.Rcode])
	}
}

// DNS names are case-insensitive, so a query in any case must find the label.
func TestLookupIsCaseInsensitive(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)
	b := bindAgent(t, reg, "laptop", "198.51.100.7")

	resp := mustQuery(t, addr, strings.ToUpper(b.FQDN(testZone)), dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Errorf("an uppercase query returned %d answers, want 1", len(resp.Answer))
	}
}

// Over the limit the server must go SILENT rather than refuse. A refusal is
// still a packet sent to whatever address the query claimed to come from, which
// is exactly the reflection being prevented.
func TestFloodIsDroppedSilently(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 2)
	b := bindAgent(t, reg, "laptop", "198.51.100.7")

	// Spend the bucket. The first few succeed; what matters is that the
	// server stops answering rather than answering with an error.
	timeouts := 0
	for range 40 {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(b.FQDN(testZone)), dns.TypeA)
		c := &dns.Client{Timeout: 300 * time.Millisecond}
		resp, _, err := c.Exchange(m, addr)
		if err != nil {
			timeouts++
			continue
		}
		if resp.Rcode == dns.RcodeRefused {
			t.Fatal("the server answered a flood with REFUSED; any answer is a reflected packet")
		}
	}
	if timeouts == 0 {
		t.Error("the rate limiter never dropped a query")
	}
}

// The limiter must not throttle a resolver making ordinary back-to-back
// queries, which is what a cold cache looks like: A then AAAA for one name.
func TestNormalResolverIsNotThrottled(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, DefaultQueriesPerSecond)
	b := bindAgent(t, reg, "laptop", "198.51.100.7", "2001:db8::7")

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := query(addr, b.FQDN(testZone), qtype)
		if err != nil {
			t.Fatalf("an ordinary %s query was dropped: %v", dns.TypeToString[qtype], err)
		}
		if len(resp.Answer) != 1 {
			t.Errorf("%s answers = %d, want 1", dns.TypeToString[qtype], len(resp.Answer))
		}
	}
}

// A resolver falls back to TCP whenever UDP truncates, so a zone served only
// over UDP fails for exactly the agents with the most records.
func TestServesOverTCP(t *testing.T) {
	reg := subdomain.NewRegistry(testZone)
	addr, _ := start(t, reg, 1000)
	b := bindAgent(t, reg, "laptop", "198.51.100.7")

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(b.FQDN(testZone)), dns.TypeA)
	c := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("TCP exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("TCP answers = %d, want 1", len(resp.Answer))
	}
}
