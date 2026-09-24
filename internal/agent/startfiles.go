package agent

import (
	"net/netip"
	"strings"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
)

// leaseAddrs returns every address the lease carries.
//
// A dual-stack lease holds one address per family, and IP is only the first of
// them. Reading IP alone would report half a lease as the whole of it, which is
// the half that produces a hostname resolving to one family and timing out on
// the other.
func leaseAddrs(lease *proto.Lease) []string {
	if len(lease.IPs) > 0 {
		return lease.IPs
	}
	if lease.IP == "" {
		return nil
	}
	return []string{lease.IP}
}

// dnsRecordsFor renders the records that must exist for a hostname, one per
// leased address, with the record type each address actually needs.
//
// It is spelled out because an operator debugging a stalled issuance otherwise
// has only a CA timeout to go on, and "point the domain at the address" is not
// enough when there are two of them and they take different record types.
func dnsRecordsFor(hostname string, addrs []string) string {
	records := make([]string, 0, len(addrs))
	for _, a := range addrs {
		kind := "A"
		if addr, err := netip.ParseAddr(a); err == nil && !addr.Is4() && !addr.Is4In6() {
			kind = "AAAA"
		}
		records = append(records, hostname+" "+kind+" "+a)
	}
	return strings.Join(records, "; ")
}

// startFileServer builds the served-directory HTTP server once the lease has
// arrived.
//
// It happens here rather than in New because the hostname a certificate is
// requested for may be the server's to choose: an agent that passed --acme
// without --domain does not know its own name until the lease says so.
func (a *Agent) startFileServer(lease *proto.Lease) error {
	if a.cfg.ServeDir == "" {
		return nil
	}

	if !a.cfg.ACME.enabled() {
		a.files = newFileServer(a.cfg.ServeDir, a.cfg.ServePort, nil, a.log)
		a.log.Warn("serving a directory over the tunnel without TLS; anyone who reaches the leased address can read it",
			"dir", a.cfg.ServeDir, "port", a.cfg.ServePort)
		return nil
	}

	hostname, err := a.cfg.ACME.resolveHostname(lease.Hostname)
	if err != nil {
		return err
	}
	certs, err := a.cfg.ACME.manager(hostname)
	if err != nil {
		return err
	}
	a.files = newFileServer(a.cfg.ServeDir, a.cfg.ServePort, certs, a.log)

	// A certificate is only as useful as the DNS record pointing at the leased
	// address, and neither this agent nor the server creates that record. Say
	// the exact record that has to exist, because an operator debugging a
	// stalled issuance otherwise has only a CA timeout to go on.
	a.log.Info("requesting a certificate on first request",
		"domain", hostname,
		"dns_records_needed", dnsRecordsFor(hostname, leaseAddrs(lease)),
		"dir", a.cfg.ServeDir)

	// A random pool moves the address on every reconnect, which breaks the DNS
	// record this certificate depends on. The server refuses --zone with
	// --random-ip, but an explicitly passed --domain reaches here regardless,
	// so the warning is the only thing standing between the operator and a
	// certificate that works until the next restart.
	if lease.PoolMode == "random" {
		a.log.Warn("this server allocates random addresses, so the DNS record for this domain will be wrong after the next reconnect",
			"domain", hostname, "ip", strings.Join(leaseAddrs(lease), ","))
	}
	return nil
}
