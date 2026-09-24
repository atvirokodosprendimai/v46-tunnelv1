package agent

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
)

// fileServer publishes a directory over the tunnel without opening a local
// port.
//
// The alternative — starting an ordinary HTTP listener on 127.0.0.1 and
// tunneling to it — would be less code and worse: it would put the directory on
// a real local port, reachable by everything else running on the machine, for
// the whole life of the tunnel. Serving the stream directly means the files
// exist on exactly one path, the tunnel, and nothing local can reach them.
type fileServer struct {
	// ports are the published ports this server answers on: one plain port
	// when there is no certificate, or 80 and 443 when there is.
	ports map[uint16]bool

	// plain serves cleartext HTTP. Without a certificate it serves the files;
	// with one it serves the ACME challenge and redirects everything else.
	plain    *http.Server
	plainLn  *streamListener
	plainPrt uint16

	// tlsSrv serves the files over TLS, and is nil when no certificate was
	// asked for.
	tlsSrv *http.Server
	tlsLn  net.Listener
	rawTLS *streamListener
}

// newFileServer builds a read-only HTTP server over dir.
//
// certs is nil for plain HTTP on plainPort. When it is set, the server ignores
// plainPort and answers on 80 and 443 instead: 443 serves the files over TLS,
// and 80 serves the HTTP-01 challenge and redirects everything else, which is
// what makes issuance work through the tunnel.
func newFileServer(dir string, plainPort uint16, certs *autocert.Manager, log *slog.Logger) *fileServer {
	files := loggingHandler(http.FileServer(http.Dir(dir)), log)

	f := &fileServer{ports: make(map[uint16]bool)}

	if certs == nil {
		f.plainPrt = plainPort
		f.ports[plainPort] = true
		f.plainLn = newStreamListener(plainPort)
		f.plain = newHTTPServer(files)
		return f
	}

	f.plainPrt = 80
	f.ports[80] = true
	f.ports[443] = true
	f.plainLn = newStreamListener(80)
	// HTTPHandler serves /.well-known/acme-challenge/ itself and hands
	// everything else to the fallback — nil means redirect to https, which is
	// the behaviour anyone reaching :80 on a certificated host expects.
	f.plain = newHTTPServer(certs.HTTPHandler(nil))

	f.rawTLS = newStreamListener(443)
	f.tlsLn = tls.NewListener(f.rawTLS, certs.TLSConfig())
	f.tlsSrv = newHTTPServer(files)
	return f
}

// newHTTPServer builds an http.Server with the timeouts a file server wants.
func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 20 * time.Second,
		// No write timeout: a large file over a slow link is the normal case
		// here, and a deadline would truncate it mid-download.
		IdleTimeout: 60 * time.Second,
	}
}

// serves reports whether this server answers on a published port.
func (f *fileServer) serves(port uint16) bool { return f.ports[port] }

// start serves until ctx is done.
func (f *fileServer) start(ctx context.Context) {
	go func() {
		<-ctx.Done()
		f.plainLn.Close()
		if f.rawTLS != nil {
			f.rawTLS.Close()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		f.plain.Shutdown(shutdownCtx)
		if f.tlsSrv != nil {
			f.tlsSrv.Shutdown(shutdownCtx)
		}
	}()

	var wg sync.WaitGroup
	if f.tlsSrv != nil {
		wg.Go(func() { f.tlsSrv.Serve(f.tlsLn) })
	}
	wg.Go(func() { f.plain.Serve(f.plainLn) })
	wg.Wait()
}

// handle passes one tunneled stream to whichever server owns its port.
func (f *fileServer) handle(stream transport.Stream, port uint16, src string) {
	// Clear the handshake deadline: it bounded the header exchange, and a
	// download is allowed to take as long as it takes.
	stream.SetDeadline(time.Time{})
	conn := &streamConn{Stream: stream, port: port, src: src}

	if f.rawTLS != nil && port == 443 {
		// Delivered raw: tls.NewListener wraps it on the way out of Accept, so
		// the handshake happens inside the TLS listener rather than here.
		f.rawTLS.deliver(conn)
		return
	}
	f.plainLn.deliver(conn)
}

// loggingHandler records each request, so an operator can see what was fetched
// through a tunnel they exposed.
func loggingHandler(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info("file request", "method", r.Method, "path", r.URL.Path, "from", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// streamListener feeds tunneled streams to an http.Server, which insists on a
// net.Listener and has no other way to be handed a connection.
type streamListener struct {
	conns chan net.Conn
	addr  net.Addr
	done  chan struct{}
	once  sync.Once
}

func newStreamListener(port uint16) *streamListener {
	return &streamListener{
		conns: make(chan net.Conn),
		addr:  tunnelAddr{port: port},
		done:  make(chan struct{}),
	}
}

// deliver hands one connection to the server, or drops it if the listener has
// closed. Dropping is right: after Close the server is shutting down and the
// client is better served by a reset than by a connection nothing will read.
func (l *streamListener) deliver(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}

// Accept implements net.Listener.
func (l *streamListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener.
func (l *streamListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr implements net.Listener.
func (l *streamListener) Addr() net.Addr { return l.addr }

// streamConn adapts a tunneled stream to net.Conn so net/http can serve it.
type streamConn struct {
	transport.Stream
	port uint16
	src  string
}

// LocalAddr reports the published port, which is what the server saw.
func (c *streamConn) LocalAddr() net.Addr { return tunnelAddr{port: c.port} }

// RemoteAddr reports the client address the server passed along. It is
// advisory — nothing authenticates it — and is used for logs only.
func (c *streamConn) RemoteAddr() net.Addr { return tunnelAddr{literal: c.src} }

// SetReadDeadline implements net.Conn on top of the stream's single deadline.
// The two deadlines cannot be set independently, so each sets both; net/http
// uses them to bound an idle connection, which either spelling achieves.
func (c *streamConn) SetReadDeadline(t time.Time) error { return c.Stream.SetDeadline(t) }

// SetWriteDeadline implements net.Conn. See SetReadDeadline.
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.Stream.SetDeadline(t) }

// tunnelAddr names an endpoint that has no socket behind it.
type tunnelAddr struct {
	port    uint16
	literal string
}

func (tunnelAddr) Network() string { return "tunnel" }

func (a tunnelAddr) String() string {
	if a.literal != "" {
		return a.literal
	}
	return net.JoinHostPort("tunnel", strconv.Itoa(int(a.port)))
}
