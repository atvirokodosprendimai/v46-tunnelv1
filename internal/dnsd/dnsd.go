// Package dnsd is the authoritative nameserver for the tunnel's zone.
//
// It answers only for names it owns: the per-agent subdomains, whose addresses
// come from the live lease registry, and the _acme-challenge TXT records that
// let the server obtain a wildcard certificate for its own zone. Everything
// else is refused.
//
// It is deliberately not a general nameserver. It does not recurse, does not
// cache, and does not serve a zone file. A tunnel's zone changes on every
// connect and disconnect, so the answer has to come from the live registry —
// anything persisted would outlive the lease it describes and hand out an
// address nobody holds.
package dnsd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/subdomain"
)

// recordTTL is how long an answer may be cached.
//
// It is short because a lease is short: an agent can disconnect at any moment,
// and a resolver holding its address for an hour keeps sending traffic to an
// address that now belongs to someone else. Thirty seconds costs a little
// query volume and bounds that window.
const recordTTL = 30

// negativeTTL is the SOA minimum, which is how long a resolver may cache an
// NXDOMAIN. Also short: a name that does not exist yet usually means an agent
// that is about to connect.
const negativeTTL = 15

// Config configures a Server.
type Config struct {
	// Registry answers what a label resolves to. Required.
	Registry *subdomain.Registry
	// Nameservers are the hostnames this zone's NS records point at. The
	// operator delegates to these at the parent zone.
	Nameservers []string
	// Hostmaster is the zone contact in SOA form (an email with the @ replaced
	// by a dot). Empty uses "hostmaster.<zone>".
	Hostmaster string
	// QueriesPerSecond bounds how many queries one source address may make.
	// Zero uses a sane default.
	//
	// This is not tuning. An authoritative nameserver on a public address is a
	// reflection and amplification vector: a small spoofed query returns a
	// larger answer to a victim, and the victim is whoever the attacker names
	// as the source. Rate limiting per source is the cheapest thing that makes
	// this server useless for that.
	QueriesPerSecond int
	// Logger receives structured events. Defaults to slog.Default().
	Logger *slog.Logger
}

// DefaultQueriesPerSecond is the per-source query allowance.
const DefaultQueriesPerSecond = 20

// Server answers DNS queries for the tunnel's zone.
type Server struct {
	registry *subdomain.Registry
	zone     string
	ns       []string
	soaMbox  string
	limiter  *limiter
	log      *slog.Logger

	mu      sync.Mutex
	udp     *dns.Server
	tcp     *dns.Server
	started time.Time
}

// New builds a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Registry == nil {
		return nil, fmt.Errorf("dnsd: no registry configured")
	}
	zone := cfg.Registry.Zone()
	if zone == "" {
		return nil, fmt.Errorf("dnsd: the registry has no zone")
	}
	hostmaster := cfg.Hostmaster
	if hostmaster == "" {
		hostmaster = "hostmaster." + zone
	}
	qps := cfg.QueriesPerSecond
	if qps <= 0 {
		qps = DefaultQueriesPerSecond
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		registry: cfg.Registry,
		zone:     zone,
		ns:       cfg.Nameservers,
		soaMbox:  dns.Fqdn(hostmaster),
		limiter:  newLimiter(qps),
		log:      log,
		started:  time.Now(),
	}, nil
}

// ListenAndServe serves DNS on addr over both UDP and TCP until ctx is done.
//
// Both are required, not a choice: a resolver retries over TCP whenever an
// answer does not fit in a UDP packet or the truncated bit is set, and a zone
// served only over UDP fails exactly for the agents with the most addresses.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	handler := dns.HandlerFunc(s.handle)

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	s.mu.Lock()
	s.udp, s.tcp = udp, tcp
	s.mu.Unlock()

	errs := make(chan error, 2)
	go func() { errs <- udp.ListenAndServe() }()
	go func() { errs <- tcp.ListenAndServe() }()
	go s.limiter.sweep(ctx)

	s.log.Info("dns listening", "addr", addr, "zone", s.zone, "nameservers", strings.Join(s.ns, ","))

	select {
	case <-ctx.Done():
		s.Shutdown()
		return ctx.Err()
	case err := <-errs:
		s.Shutdown()
		return err
	}
}

// Shutdown stops both listeners.
func (s *Server) Shutdown() {
	s.mu.Lock()
	udp, tcp := s.udp, s.tcp
	s.udp, s.tcp = nil, nil
	s.mu.Unlock()
	if udp != nil {
		udp.Shutdown()
	}
	if tcp != nil {
		tcp.Shutdown()
	}
}

// handle answers one query.
func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		s.refuse(w, req, dns.RcodeFormatError)
		return
	}
	if source, ok := sourceAddr(w); ok && !s.limiter.allow(source) {
		// Dropped rather than refused. An answer of any kind, including a
		// refusal, is still a packet sent to whatever address the query
		// claimed to come from — which is the amplification being prevented.
		return
	}

	q := req.Question[0]
	name := subdomain.Normalize(q.Name)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	// No recursion, ever. Advertising it invites resolvers to use this server
	// for lookups it has no business making, which is the other half of the
	// amplification problem.
	resp.RecursionAvailable = false

	switch {
	case name == s.zone:
		s.answerZoneApex(resp, q)
	case strings.HasSuffix(name, "."+s.zone):
		s.answerWithinZone(resp, q, name)
	default:
		// Not our zone. REFUSED rather than NXDOMAIN: NXDOMAIN asserts the name
		// does not exist, which this server has no standing to say about a zone
		// it is not authoritative for.
		resp.Authoritative = false
		resp.Rcode = dns.RcodeRefused
	}

	if err := w.WriteMsg(resp); err != nil {
		s.log.Debug("dns write failed", "err", err)
	}
}

// answerZoneApex handles queries for the zone itself.
func (s *Server) answerZoneApex(resp *dns.Msg, q dns.Question) {
	switch q.Qtype {
	case dns.TypeSOA:
		resp.Answer = append(resp.Answer, s.soa())
	case dns.TypeNS:
		resp.Answer = append(resp.Answer, s.nsRecords()...)
	case dns.TypeANY:
		// RFC 8482: an ANY query is answered minimally rather than with
		// everything known, because "send me everything" is the single most
		// useful query shape for an amplification attack.
		resp.Answer = append(resp.Answer, s.soa())
	default:
		// The name exists but has no record of this type: NOERROR with an
		// empty answer and the SOA in authority, which is what tells a
		// resolver to cache the negative rather than retry.
		resp.Ns = append(resp.Ns, s.soa())
	}
}

// answerWithinZone handles queries for names under the zone.
func (s *Server) answerWithinZone(resp *dns.Msg, q dns.Question, name string) {
	if q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY {
		if values, ok := s.registry.TXT(name); ok {
			for _, v := range values {
				resp.Answer = append(resp.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: recordTTL},
					Txt: []string{v},
				})
			}
			if len(resp.Answer) > 0 {
				return
			}
		}
	}

	label := strings.TrimSuffix(name, "."+s.zone)
	// Only a direct child of the zone can be an agent. A deeper name is not a
	// tunnel and must not be answered by trimming down to one.
	if strings.Contains(label, ".") {
		s.nxdomain(resp)
		return
	}

	addrs, ok := s.registry.Lookup(label)
	if !ok {
		s.nxdomain(resp)
		return
	}

	for _, addr := range addrs {
		switch {
		case q.Qtype == dns.TypeA && addr.Is4(), q.Qtype == dns.TypeANY && addr.Is4():
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: recordTTL},
				A:   net.IP(addr.AsSlice()),
			})
		case q.Qtype == dns.TypeAAAA && !addr.Is4(), q.Qtype == dns.TypeANY && !addr.Is4():
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: recordTTL},
				AAAA: net.IP(addr.AsSlice()),
			})
		}
	}

	// The name exists. An empty answer here means it has no record of the type
	// asked for — a dual-stack agent asked for A when it holds only IPv6, say —
	// which is NOERROR with the SOA in authority, NOT NXDOMAIN. Saying the name
	// does not exist would make a resolver stop trying the other family.
	if len(resp.Answer) == 0 {
		resp.Ns = append(resp.Ns, s.soa())
	}
}

// nxdomain marks the response as a cacheable "no such name".
func (s *Server) nxdomain(resp *dns.Msg) {
	resp.Rcode = dns.RcodeNameError
	resp.Ns = append(resp.Ns, s.soa())
}

// refuse answers with a bare error code.
func (s *Server) refuse(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	w.WriteMsg(resp)
}

// soa builds the zone's SOA record. Its Minimum field is the negative cache
// TTL, which is what bounds how long a resolver remembers that an agent's name
// did not exist.
func (s *Server) soa() *dns.SOA {
	primary := s.soaPrimary()
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(s.zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: recordTTL},
		Ns:      primary,
		Mbox:    s.soaMbox,
		Serial:  uint32(s.started.Unix()),
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  negativeTTL,
	}
}

// soaPrimary names the zone's primary nameserver.
func (s *Server) soaPrimary() string {
	if len(s.ns) > 0 {
		return dns.Fqdn(s.ns[0])
	}
	// No nameserver was configured. The SOA still has to name one, and naming
	// the zone itself is the least wrong answer available — it is visibly a
	// placeholder rather than a plausible hostname that resolves elsewhere.
	return dns.Fqdn(s.zone)
}

// nsRecords builds the zone's NS set.
func (s *Server) nsRecords() []dns.RR {
	out := make([]dns.RR, 0, len(s.ns))
	for _, host := range s.ns {
		out = append(out, &dns.NS{
			Hdr: dns.RR_Header{Name: dns.Fqdn(s.zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: recordTTL},
			Ns:  dns.Fqdn(host),
		})
	}
	return out
}

// sourceAddr extracts the querying address for rate limiting.
func sourceAddr(w dns.ResponseWriter) (netip.Addr, bool) {
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(a.IP)
		return addr.Unmap(), ok
	case *net.TCPAddr:
		addr, ok := netip.AddrFromSlice(a.IP)
		return addr.Unmap(), ok
	default:
		return netip.Addr{}, false
	}
}
