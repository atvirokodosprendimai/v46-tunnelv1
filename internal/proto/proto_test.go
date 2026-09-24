package proto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
)

func TestControlRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	c := NewControlConn(&buf)

	ports, err := portspec.Parse("80/udp,443")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sent := []Control{
		{Hello: &Hello{Version: Version, Token: "t0k", OS: "darwin", Arch: "arm64", Ports: ports}},
		{Lease: &Lease{IP: "10.0.0.7", AgentID: "laptop", Bound: ports, KeepaliveSec: 15}},
		{Ping: true},
		{Pong: true},
		{Error: &Error{Message: "pool exhausted"}},
	}
	for _, msg := range sent {
		if err := c.Send(msg); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	back := NewControlConn(&buf)
	for i, want := range sent {
		got, err := back.Recv()
		if err != nil {
			t.Fatalf("Recv %d: %v", i, err)
		}
		switch {
		case want.Hello != nil:
			if got.Hello == nil || got.Hello.Token != "t0k" || portspec.Format(got.Hello.Ports) != portspec.Format(ports) {
				t.Errorf("hello round trip = %+v", got.Hello)
			}
		case want.Lease != nil:
			if got.Lease == nil || got.Lease.IP != "10.0.0.7" || got.Lease.KeepaliveSec != 15 {
				t.Errorf("lease round trip = %+v", got.Lease)
			}
		case want.Error != nil:
			if got.Error == nil || got.Error.Message != "pool exhausted" {
				t.Errorf("error round trip = %+v", got.Error)
			}
		case want.Ping:
			if !got.Ping {
				t.Error("ping did not survive the round trip")
			}
		case want.Pong:
			if !got.Pong {
				t.Error("pong did not survive the round trip")
			}
		}
	}
	if _, err := back.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("Recv after the last message = %v, want io.EOF", err)
	}
}

func TestControlRecvRejectsGarbage(t *testing.T) {
	c := NewControlConn(bytes.NewBufferString("not json\n"))
	if _, err := c.Recv(); err == nil {
		t.Fatal("Recv accepted a malformed control message")
	}
}

func TestStreamKindRoundTrip(t *testing.T) {
	for _, k := range []StreamKind{KindControl, KindUDP, KindTCP} {
		var buf bytes.Buffer
		if err := WriteStreamKind(&buf, k); err != nil {
			t.Fatalf("WriteStreamKind: %v", err)
		}
		got, err := ReadStreamKind(&buf)
		if err != nil {
			t.Fatalf("ReadStreamKind: %v", err)
		}
		if got != k {
			t.Errorf("kind round trip = %v, want %v", got, k)
		}
	}
}

func TestTCPOpenRoundTrip(t *testing.T) {
	tests := []TCPOpen{
		{Port: 1234, Src: "203.0.113.9:51000"},
		{Port: 443, Src: "[2001:db8::1]:40000"},
		{Port: 22, Src: ""},
	}
	for _, want := range tests {
		var buf bytes.Buffer
		if err := WriteTCPOpen(&buf, want); err != nil {
			t.Fatalf("WriteTCPOpen: %v", err)
		}
		got, err := ReadTCPOpen(&buf)
		if err != nil {
			t.Fatalf("ReadTCPOpen: %v", err)
		}
		if got != want {
			t.Errorf("TCPOpen round trip = %+v, want %+v", got, want)
		}
		if buf.Len() != 0 {
			t.Errorf("ReadTCPOpen left %d bytes unconsumed; a data stream would start mid-payload", buf.Len())
		}
	}
}

// The source address is length-prefixed with a single byte, so an over-long one
// has to be truncated rather than corrupting the frame it precedes.
func TestTCPOpenTruncatesOverlongSrc(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTCPOpen(&buf, TCPOpen{Port: 80, Src: strings.Repeat("x", maxSrcLen+50)}); err != nil {
		t.Fatalf("WriteTCPOpen: %v", err)
	}
	got, err := ReadTCPOpen(&buf)
	if err != nil {
		t.Fatalf("ReadTCPOpen: %v", err)
	}
	if len(got.Src) != maxSrcLen {
		t.Errorf("truncated src length = %d, want %d", len(got.Src), maxSrcLen)
	}
	if buf.Len() != 0 {
		t.Errorf("frame desynchronised: %d bytes left over", buf.Len())
	}
}

func TestOpenResultRoundTrip(t *testing.T) {
	for _, want := range []OpenResult{OpenOK, OpenRefused, OpenNotAllow} {
		var buf bytes.Buffer
		if err := WriteOpenResult(&buf, want); err != nil {
			t.Fatalf("WriteOpenResult: %v", err)
		}
		got, err := ReadOpenResult(&buf)
		if err != nil {
			t.Fatalf("ReadOpenResult: %v", err)
		}
		if got != want {
			t.Errorf("OpenResult round trip = %v, want %v", got, want)
		}
	}
}

func TestUDPFrameRoundTrip(t *testing.T) {
	payload := []byte("a dns query, say")
	frame := AppendUDPFrame(nil, 0xDEADBEEFCAFEF00D, 53, payload)
	if len(frame) != UDPHeaderLen+len(payload) {
		t.Fatalf("frame length = %d, want %d", len(frame), UDPHeaderLen+len(payload))
	}
	flowID, port, got, err := ParseUDPFrame(frame)
	if err != nil {
		t.Fatalf("ParseUDPFrame: %v", err)
	}
	if flowID != 0xDEADBEEFCAFEF00D || port != 53 {
		t.Errorf("flow/port = %#x/%d, want %#x/53", flowID, port, uint64(0xDEADBEEFCAFEF00D))
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

// A zero-length UDP payload is a real packet, not an absent one, and the frame
// has to survive the round trip rather than being mistaken for a truncation.
func TestUDPFrameEmptyPayload(t *testing.T) {
	frame := AppendUDPFrame(nil, 1, 9, nil)
	_, _, payload, err := ParseUDPFrame(frame)
	if err != nil {
		t.Fatalf("ParseUDPFrame: %v", err)
	}
	if len(payload) != 0 {
		t.Errorf("payload = %q, want empty", payload)
	}
}

func TestParseUDPFrameRejectsShort(t *testing.T) {
	if _, _, _, err := ParseUDPFrame(make([]byte, UDPHeaderLen-1)); !errors.Is(err, ErrShortUDPFrame) {
		t.Errorf("ParseUDPFrame(short) = %v, want ErrShortUDPFrame", err)
	}
}

func TestUDPStreamFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := AppendUDPFrame(nil, 7, 5353, []byte("multicast dns"))
	if err := WriteUDPStreamFrame(&buf, want); err != nil {
		t.Fatalf("WriteUDPStreamFrame: %v", err)
	}
	// Two frames back to back, to prove the length prefix actually delimits.
	if err := WriteUDPStreamFrame(&buf, want); err != nil {
		t.Fatalf("WriteUDPStreamFrame: %v", err)
	}
	for i := range 2 {
		got, err := ReadUDPStreamFrame(&buf)
		if err != nil {
			t.Fatalf("ReadUDPStreamFrame %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("frame %d = %q, want %q", i, got, want)
		}
	}
}

// A length prefix is attacker-controlled on an authenticated-but-hostile
// session, so an absurd one has to be refused rather than turned into an
// allocation.
func TestReadUDPStreamFrameRejectsAbsurdLength(t *testing.T) {
	for _, n := range []uint32{0, UDPHeaderLen - 1, UDPHeaderLen + MaxUDPPayload + 1, 1 << 30} {
		var buf bytes.Buffer
		buf.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
		if _, err := ReadUDPStreamFrame(&buf); err == nil {
			t.Errorf("ReadUDPStreamFrame accepted a length of %d", n)
		}
	}
}
