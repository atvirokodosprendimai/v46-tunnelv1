package server

import (
	"fmt"
	"strings"
)

// maxLabelLen is the DNS limit on a single label.
const maxLabelLen = 63

// validateZone rejects a zone a hostname could not be built under. The checks
// are shallow on purpose — whether the zone exists is DNS's business — but they
// catch the spellings that would produce a syntactically invalid hostname and
// therefore an opaque certificate failure much later.
func validateZone(zone string) error {
	switch {
	case strings.Contains(zone, "/") || strings.Contains(zone, ":"):
		return fmt.Errorf("server: --zone %q should be a domain, not a URL or host:port", zone)
	case strings.HasPrefix(zone, "."), strings.HasSuffix(zone, "."):
		return fmt.Errorf("server: --zone %q should not start or end with a dot", zone)
	case !strings.Contains(zone, "."):
		return fmt.Errorf("server: --zone %q has no dot; a public CA will not issue under a bare label", zone)
	}
	return nil
}

// hostnameFor names an agent under the server's zone.
//
// It returns empty when there is no zone or the agent did not ask, which is
// what the lease's omitempty relies on: an absent hostname and an empty one
// must not be different answers.
func (s *Server) hostnameFor(agentID string, wanted bool) string {
	if !wanted || s.zone == "" {
		return ""
	}
	label := dnsLabel(agentID)
	if label == "" {
		return ""
	}
	return label + "." + s.zone
}

// dnsLabel turns an agent id into something usable as a DNS label.
//
// Agent ids come from an operator-written tokens file and are not constrained
// to DNS syntax, so a name like "M's laptop" has to become something a
// certificate can be issued for rather than producing a request the CA rejects
// for reasons that do not mention the tokens file.
func dnsLabel(agentID string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(agentID) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			// Collapse runs of anything else into one dash, so "M's  laptop"
			// does not become "m-s--laptop".
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
		if b.Len() >= maxLabelLen {
			break
		}
	}
	label := strings.Trim(b.String(), "-")
	if len(label) > maxLabelLen {
		label = strings.Trim(label[:maxLabelLen], "-")
	}
	return label
}
