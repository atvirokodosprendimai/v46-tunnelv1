package agent

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/proto"
)

// pipeStream adapts one end of a net.Pipe to transport.Stream, so serveStream
// can be driven without a server.
type pipeStream struct{ net.Conn }

func (p pipeStream) SetDeadline(t time.Time) error { return p.Conn.SetDeadline(t) }

// The agent enforces its own allow list because it is the side that actually
// reaches localhost. A server that is compromised, misconfigured, or simply
// newer must not be able to talk the agent into opening a port its operator
// never named — so the check cannot live only on the server.
func TestServeStreamRefusesAnUndeclaredPort(t *testing.T) {
	ag, err := New(Config{
		Server: "127.0.0.1:1",
		Token:  "t",
		Ports:  []portspec.Spec{{Port: 4444, Proto: portspec.TCP}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	client, agentSide := net.Pipe()
	defer client.Close()
	go ag.serveStream(pipeStream{agentSide})

	if err := proto.WriteStreamKind(client, proto.KindTCP); err != nil {
		t.Fatalf("WriteStreamKind: %v", err)
	}
	// 5555 was never declared. If the check were server-only, the agent would
	// dial it here.
	if err := proto.WriteTCPOpen(client, proto.TCPOpen{Port: 5555, Src: "198.51.100.1:1234"}); err != nil {
		t.Fatalf("WriteTCPOpen: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := proto.ReadOpenResult(client)
	if err != nil {
		t.Fatalf("ReadOpenResult: %v", err)
	}
	if res != proto.OpenNotAllow {
		t.Errorf("agent answered %v for an undeclared port, want %v", res, proto.OpenNotAllow)
	}
}

// A declared port whose local service is not running must be refused rather
// than left hanging: the server resets the client on this verdict, and without
// it the client would wait for a connection that will never be made.
func TestServeStreamRefusesWhenTheLocalDialFails(t *testing.T) {
	// Reserve a port and release it, so nothing is listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()

	ag, err := New(Config{
		Server:      "127.0.0.1:1",
		Token:       "t",
		Ports:       []portspec.Spec{{Port: port, Proto: portspec.TCP}},
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	client, agentSide := net.Pipe()
	defer client.Close()
	go ag.serveStream(pipeStream{agentSide})

	proto.WriteStreamKind(client, proto.KindTCP)
	proto.WriteTCPOpen(client, proto.TCPOpen{Port: port, Src: "198.51.100.1:1234"})
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	res, err := proto.ReadOpenResult(client)
	if err != nil {
		t.Fatalf("ReadOpenResult: %v", err)
	}
	if res != proto.OpenRefused {
		t.Errorf("agent answered %v for a dead local port, want %v", res, proto.OpenRefused)
	}
}

// Serving a directory publishes its port whether or not the operator listed it
// in --ports, because a directory on a port nobody can reach is not a
// configuration anyone wants.
func TestServeDirAddsItsPort(t *testing.T) {
	ag, err := New(Config{
		Server:    "127.0.0.1:1",
		Token:     "t",
		ServeDir:  t.TempDir(),
		ServePort: 8080,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !ag.allowed[portspec.Spec{Port: 8080, Proto: portspec.TCP}] {
		t.Error("the served port was not published")
	}
	if ag.files == nil {
		t.Error("no file server was built for ServeDir")
	}
}

func TestNewRejectsBadServeDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatalf("creating a file: %v", err)
	}
	tests := []struct {
		name    string
		cfg     Config
		wantSub string
	}{
		{"no port", Config{Server: "h:1", ServeDir: t.TempDir()}, "needs a port"},
		{"missing directory", Config{Server: "h:1", ServeDir: "/no/such/dir", ServePort: 80}, "cannot serve"},
		{"not a directory", Config{Server: "h:1", ServeDir: file, ServePort: 80}, "not a directory"},
		{"nothing declared", Config{Server: "h:1"}, "no ports declared"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if err == nil {
				t.Fatal("New succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantSub)
			}
		})
	}
}
