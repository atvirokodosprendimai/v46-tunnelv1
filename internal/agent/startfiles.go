package agent

import (
	"fmt"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
)

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
		"dns_record_needed", fmt.Sprintf("%s -> %s", hostname, lease.IP),
		"dir", a.cfg.ServeDir)

	// A random pool moves the address on every reconnect, which breaks the DNS
	// record this certificate depends on. The server refuses --zone with
	// --random-ip, but an explicitly passed --domain reaches here regardless,
	// so the warning is the only thing standing between the operator and a
	// certificate that works until the next restart.
	if lease.PoolMode == "random" {
		a.log.Warn("this server allocates random addresses, so the DNS record for this domain will be wrong after the next reconnect",
			"domain", hostname, "ip", lease.IP)
	}
	return nil
}
