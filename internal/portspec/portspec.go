// Package portspec parses the port declaration an agent uses to say which of
// its local ports it wants published on its leased address.
//
// The declaration is what keeps this system small. Because the agent names the
// ports, the server binds exactly that set on the leased IP and never has to
// own all 65535 — which is what would otherwise force a kernel-assisted capture
// (TPROXY plus nftables, root, Linux only) instead of plain listeners.
package portspec

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Proto is the transport protocol a declared port is published on.
type Proto uint8

// The protocols a port may be published on. TCP is the default when a
// declaration names no protocol, because it is overwhelmingly the common case.
const (
	TCP Proto = iota
	UDP
)

// String returns the lowercase protocol name used in a declaration.
func (p Proto) String() string {
	if p == UDP {
		return "udp"
	}
	return "tcp"
}

// MaxSpecs bounds how many ports one declaration may expand to. A range is a
// convenience for a handful of adjacent ports, not a way to ask for the whole
// port space back: "1-65535" would recreate exactly the 65k-listener design
// that declaring ports exists to avoid, so it is refused by name rather than
// accepted and then discovered at bind time.
const MaxSpecs = 4096

// Spec is one published port: a port number and the protocol it is served on.
type Spec struct {
	Port  uint16
	Proto Proto
}

// String renders the spec in declaration syntax, e.g. "443/tcp".
func (s Spec) String() string { return strconv.Itoa(int(s.Port)) + "/" + s.Proto.String() }

// MarshalText implements encoding.TextMarshaler so a Spec crosses the control
// stream as "443/tcp" rather than as a struct whose field order is a wire
// contract nobody wrote down.
func (s Spec) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler, accepting exactly what
// MarshalText produces plus the shorthands Parse allows.
func (s *Spec) UnmarshalText(b []byte) error {
	specs, err := parseEntry(string(b))
	if err != nil {
		return err
	}
	if len(specs) != 1 {
		return fmt.Errorf("portspec: %q is a range, not a single port", b)
	}
	*s = specs[0]
	return nil
}

// ErrEmpty reports a declaration that names no ports at all. It is a distinct
// error because an agent with an empty --ports has asked for a lease it cannot
// use, which is a usage mistake rather than a parse failure.
var ErrEmpty = errors.New("portspec: no ports declared")

// Parse turns a declaration such as "80/udp,443,5000-5100/udp,53/tcp+udp" into
// a deduplicated, sorted set of specs. Entries are comma separated; each is a
// port or an inclusive PORT-PORT range, optionally suffixed with "/tcp",
// "/udp", or "/tcp+udp". Whitespace around entries is ignored.
func Parse(decl string) ([]Spec, error) {
	seen := make(map[Spec]struct{})
	var out []Spec
	for _, entry := range strings.Split(decl, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		specs, err := parseEntry(entry)
		if err != nil {
			return nil, err
		}
		for _, s := range specs {
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
			if len(out) > MaxSpecs {
				return nil, fmt.Errorf("portspec: declaration expands past %d ports; name the ports you need instead of a wide range", MaxSpecs)
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrEmpty
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out, nil
}

// Format renders a set of specs back into declaration syntax, so a server can
// echo in the lease exactly what it bound.
func Format(specs []Spec) string {
	parts := make([]string, len(specs))
	for i, s := range specs {
		parts[i] = s.String()
	}
	return strings.Join(parts, ",")
}

// parseEntry parses a single comma-free entry into one spec per (port, proto).
func parseEntry(entry string) ([]Spec, error) {
	ports, protos := entry, "tcp"
	if slash := strings.LastIndex(entry, "/"); slash >= 0 {
		ports, protos = entry[:slash], strings.ToLower(entry[slash+1:])
	}

	var wanted []Proto
	switch protos {
	case "tcp":
		wanted = []Proto{TCP}
	case "udp":
		wanted = []Proto{UDP}
	case "tcp+udp", "udp+tcp", "both":
		wanted = []Proto{TCP, UDP}
	default:
		return nil, fmt.Errorf("portspec: %q: unknown protocol %q (want tcp, udp, or tcp+udp)", entry, protos)
	}

	lo, hi, err := parseRange(ports)
	if err != nil {
		return nil, fmt.Errorf("portspec: %q: %w", entry, err)
	}

	out := make([]Spec, 0, int(hi-lo+1)*len(wanted))
	for p := int(lo); p <= int(hi); p++ {
		for _, proto := range wanted {
			out = append(out, Spec{Port: uint16(p), Proto: proto})
		}
	}
	return out, nil
}

// parseRange parses "80" or "5000-5100" into an inclusive bound pair.
func parseRange(s string) (lo, hi uint16, err error) {
	before, after, isRange := strings.Cut(s, "-")
	lo, err = parsePort(before)
	if err != nil {
		return 0, 0, err
	}
	if !isRange {
		return lo, lo, nil
	}
	hi, err = parsePort(after)
	if err != nil {
		return 0, 0, err
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("range %d-%d runs backwards", lo, hi)
	}
	return lo, hi, nil
}

// parsePort parses a single port number, rejecting 0 — which is not a port an
// agent can be listening on, and which means "pick one for me" to the kernel.
func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", n)
	}
	return uint16(n), nil
}
