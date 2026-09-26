package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/dnsd"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/subdomain"
)

// startDNS brings up the authoritative nameserver for the tunnel's zone.
//
// It starts before any agent connects, because a zone that is delegated here
// and does not answer is worse than one that answers NXDOMAIN: a resolver
// caches a SERVFAIL for the whole zone, not just the name it asked about.
func startDNS(ctx context.Context, cmd *cli.Command, registry *subdomain.Registry, log *slog.Logger) error {
	nameservers := cmd.StringSlice("dns-ns")
	if len(nameservers) == 0 {
		// The zone still needs an NS set to be well-formed, and naming the zone
		// itself is visibly a placeholder rather than a plausible hostname
		// pointing somewhere real.
		log.Warn("no --dns-ns given, so the zone's NS records name the zone itself; delegation will not work until you pass the real nameserver hostnames",
			"zone", registry.Zone())
	}

	srv, err := dnsd.New(dnsd.Config{
		Registry:         registry,
		Nameservers:      nameservers,
		QueriesPerSecond: cmd.Int("dns-qps"),
		Logger:           log,
	})
	if err != nil {
		return err
	}

	addr := cmd.String("dns-listen")
	ready := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe(ctx, addr)
		select {
		case ready <- err:
		default:
			if err != nil && ctx.Err() == nil {
				log.Error("nameserver stopped", "err", err)
			}
		}
	}()

	// A bind failure is the common case on port 53 — it is privileged, and the
	// process usually is not. Surfacing it here makes it a startup error naming
	// the cause, rather than a zone that silently never answers.
	select {
	case err := <-ready:
		if err != nil {
			return fmt.Errorf("serving DNS on %s: %w (port 53 is privileged: run as root or grant CAP_NET_BIND_SERVICE)", addr, err)
		}
	default:
	}

	log.Info("authoritative nameserver started",
		"addr", addr,
		"zone", registry.Zone(),
		"ns", strings.Join(nameservers, ","),
		"delegate", delegationHint(registry.Zone(), nameservers))
	return nil
}

// delegationHint spells out the records the parent zone needs, because "point
// NS at it" is not enough to act on without knowing the exact shape.
func delegationHint(zone string, nameservers []string) string {
	if len(nameservers) == 0 {
		return "pass --dns-ns to get the records you need"
	}
	parts := make([]string, 0, len(nameservers))
	for _, ns := range nameservers {
		parts = append(parts, zone+" NS "+ns)
	}
	return strings.Join(parts, "; ")
}
