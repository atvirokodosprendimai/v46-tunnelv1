package portspec

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseDeclaration(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare port defaults to tcp", "443", "443/tcp"},
		{"explicit udp", "80/udp", "80/udp"},
		{"the example from the request", "80/udp,443", "80/udp,443/tcp"},
		{"both protocols", "53/tcp+udp", "53/tcp,53/udp"},
		{"inclusive range", "8000-8002", "8000/tcp,8001/tcp,8002/tcp"},
		{"sorted by port then proto", "443,80/udp,22", "22/tcp,80/udp,443/tcp"},
		{"duplicates collapse", "443,443/tcp,443", "443/tcp"},
		{"whitespace is ignored", " 80 , 443 ", "80/tcp,443/tcp"},
		{"empty entries are skipped", "80,,443,", "80/tcp,443/tcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			if Format(got) != tt.want {
				t.Errorf("Parse(%q) = %q, want %q", tt.in, Format(got), tt.want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantSub string
	}{
		{"port zero", "0", "out of range"},
		{"port above range", "65536", "out of range"},
		{"not a number", "http", "not a port number"},
		{"unknown protocol", "443/sctp", "unknown protocol"},
		{"backwards range", "500-400", "runs backwards"},
		{"the whole port space", "1-65535", "expands past"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.in)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want an error", tt.in)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("Parse(%q) error = %v, want it to mention %q", tt.in, err, tt.wantSub)
			}
		})
	}
}

// An agent that declares nothing has asked for a lease it cannot use, which is
// a different mistake from a malformed declaration and is reported as its own
// error so a caller can say so.
func TestParseEmptyDeclaration(t *testing.T) {
	for _, in := range []string{"", "   ", ",,"} {
		if _, err := Parse(in); !errors.Is(err, ErrEmpty) {
			t.Errorf("Parse(%q) error = %v, want ErrEmpty", in, err)
		}
	}
}

// The control stream carries specs as JSON, so the text form has to survive a
// round trip — a server echoing back what it bound is the agent's only
// confirmation that the two sides agree on the set.
func TestSpecJSONRoundTrip(t *testing.T) {
	in, err := Parse("80/udp,443,22")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `["22/tcp","80/udp","443/tcp"]`; string(encoded) != want {
		t.Errorf("Marshal = %s, want %s", encoded, want)
	}
	var out []Spec
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if Format(out) != Format(in) {
		t.Errorf("round trip = %q, want %q", Format(out), Format(in))
	}
}

func TestUnmarshalTextRejectsARange(t *testing.T) {
	var s Spec
	if err := s.UnmarshalText([]byte("100-200")); err == nil {
		t.Fatal("UnmarshalText accepted a range into a single Spec")
	}
}

// MaxSpecs is a bound on the expansion, not on the declaration's length: a
// range landing exactly on the cap has to be accepted, or the error message
// names a limit that is off by one from the one enforced.
func TestParseAcceptsExactlyMaxSpecs(t *testing.T) {
	got, err := Parse("1-4096")
	if err != nil {
		t.Fatalf("Parse of exactly MaxSpecs ports: %v", err)
	}
	if len(got) != MaxSpecs {
		t.Errorf("got %d specs, want %d", len(got), MaxSpecs)
	}
}
