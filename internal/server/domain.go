package server

import (
	"fmt"
	"net/netip"
	"strings"
)

// validateDomain rejects a domain the server could not serve as a zone.
//
// The checks are shallow on purpose — whether the zone is actually delegated is
// DNS's business, and this server cannot know — but they catch the spellings
// that would produce syntactically invalid subdomains and therefore an opaque
// certificate failure much later.
func validateDomain(domain string) error {
	switch {
	case strings.Contains(domain, "/") || strings.Contains(domain, ":"):
		return fmt.Errorf("server: --domain %q should be a domain, not a URL or host:port", domain)
	case strings.HasPrefix(domain, "*."):
		// The wildcard is what the server requests a certificate FOR; it is not
		// how the zone is named. Accepting it here would produce subdomains
		// like "<label>.*.example.com", which resolve nowhere.
		return fmt.Errorf("server: --domain %q should be the zone itself, not a wildcard; pass %q and the wildcard certificate is derived from it", domain, strings.TrimPrefix(domain, "*."))
	case strings.HasPrefix(domain, "."), strings.HasSuffix(domain, "."):
		return fmt.Errorf("server: --domain %q should not start or end with a dot", domain)
	case !strings.Contains(domain, "."):
		return fmt.Errorf("server: --domain %q has no dot; a public CA will not issue under a bare label", domain)
	}
	return nil
}

// Wildcard is the name a certificate for this zone covers.
func Wildcard(domain string) string { return "*." + domain }

// bindSubdomain mints this session's name, or returns empty when the server
// serves no domain.
func (s *Server) bindSubdomain(agentID string, addrs []netip.Addr) (string, error) {
	if s.registry == nil {
		return "", nil
	}
	binding, err := s.registry.Bind(agentID, addrs)
	if err != nil {
		return "", err
	}
	return binding.FQDN(s.domain), nil
}

// releaseSubdomain retires this session's name.
func (s *Server) releaseSubdomain(agentID string) {
	if s.registry != nil {
		s.registry.Release(agentID)
	}
}
