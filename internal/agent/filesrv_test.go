package agent

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serveOnce runs a file server, feeds it one tunneled stream on the given port,
// and returns the HTTP response to req.
func serveOnce(t *testing.T, f *fileServer, port uint16, req *http.Request) *http.Response {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() { defer close(done); f.start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("file server did not stop within 5s")
		}
	})

	client, agentSide := net.Pipe()
	t.Cleanup(func() { client.Close() })
	go f.handle(pipeStream{agentSide}, port, "198.51.100.1:5000")

	client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := req.Write(client); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func mustRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func testDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>the index</h1>"), 0o644); err != nil {
		t.Fatalf("writing index.html: %v", err)
	}
	return dir
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Without a certificate the directory is served in the clear on its own port.
// This is the baseline the ACME case has to differ from.
func TestFileServerPlainServesTheFiles(t *testing.T) {
	f := newFileServer(testDir(t), 8080, nil, quietLogger())

	resp := serveOnce(t, f, 8080, mustRequest(t, "http://files.example.com/"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "the index") {
		t.Errorf("body = %q, want the contents of index.html", body)
	}
	if f.serves(80) || f.serves(443) {
		t.Error("the plain server claimed the ACME ports")
	}
}

// With a certificate the directory moves to 80 and 443, and :80 stops serving
// files: it carries the HTTP-01 challenge and redirects everything else.
//
// The discriminator is deliberate. Both configurations answer on :80, so
// "something responded" proves nothing — but the plain server returns 200 with
// the index at "/", and the ACME one must redirect. If the certificate wiring
// were skipped, this test would see a 200 and fail.
func TestFileServerWithCertificateRedirectsPlainHTTP(t *testing.T) {
	certs, err := ACMEConfig{
		Domain:    "files.example.com",
		AcceptTOS: true,
		CacheDir:  t.TempDir(),
	}.manager("files.example.com")
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	f := newFileServer(testDir(t), 8080, certs, quietLogger())

	if !f.serves(80) || !f.serves(443) {
		t.Fatalf("certificated server answers on 80=%v 443=%v, want both", f.serves(80), f.serves(443))
	}
	if f.serves(8080) {
		t.Error("the plain --dir-port is still served alongside the TLS ports")
	}

	resp := serveOnce(t, f, 80, mustRequest(t, "http://files.example.com/"))
	if resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want a redirect to https (body %q)", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "https://") {
		t.Errorf("Location = %q, want an https URL", loc)
	}
}

// The HTTP-01 challenge path has to be reachable through the tunnel on :80 —
// that is the whole reason issuance works from behind a tunnel at all.
//
// An unknown token is a 404 from autocert, which is the correct answer to a
// challenge nobody issued. What matters is that the path is answered by the
// challenge handler rather than by the file server: the file server would look
// for a file of that name and also 404, so the assertion is on the body being
// empty of the directory listing rather than on the status alone.
func TestFileServerWithCertificateServesTheChallengePath(t *testing.T) {
	certs, err := ACMEConfig{
		Domain:    "files.example.com",
		AcceptTOS: true,
		CacheDir:  t.TempDir(),
	}.manager("files.example.com")
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	f := newFileServer(testDir(t), 8080, certs, quietLogger())

	resp := serveOnce(t, f, 80, mustRequest(t, "http://files.example.com/.well-known/acme-challenge/not-a-real-token"))

	// Not a redirect: HTTPHandler answers the challenge path itself and only
	// redirects everything else. A 301 here would mean the challenge would be
	// bounced to https, which is not where a CA looks for it.
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
		t.Fatalf("the challenge path was redirected (status %d); a CA would never follow it", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "the index") {
		t.Errorf("the challenge path was served by the file server, not the ACME handler: body %q", body)
	}
}
