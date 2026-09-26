// Command tunnel-agent connects to a tunnel server and serves the local ports
// it declared. It runs on Linux and macOS and needs no privileges: every port
// it touches is a dial to its own target host, never a listen.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/agent"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tlsutil"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/quictp"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/wstp"
)

func main() {
	cmd := &cli.Command{
		Name:  "tunnel-agent",
		Usage: "publish local ports on an address leased from a tunnel server",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server", Usage: "tunnel server host:port", Required: true},
			&cli.StringFlag{Name: "token", Usage: "authentication token", Required: true, Sources: cli.EnvVars("TUNNEL_TOKEN")},
			&cli.StringFlag{
				Name:  "ports",
				Usage: "local ports to publish, e.g. '80/udp,443,5000-5100/udp' (protocol defaults to tcp)",
			},
			&cli.StringFlag{
				Name:  "dir",
				Usage: "serve this directory over the tunnel as a read-only file server (index.html when present, a listing otherwise)",
			},
			&cli.UintFlag{
				Name:  "dir-port",
				Value: 8080,
				Usage: "published port for --dir; added to --ports automatically, and ignored when a certificate is requested (that moves --dir to 80 and 443)",
			},
			&cli.UintFlag{
				Name:  "https-backend",
				Usage: "ask the server to terminate TLS on 443 for your assigned subdomain and forward the plaintext to this local port. With --dir and no port given, the directory is used. ⚠ The server decrypts, so it sees the plaintext",
			},
			&cli.BoolFlag{
				Name:  "https",
				Usage: "shorthand for --https-backend pointing at --dir",
			},
			&cli.StringFlag{
				Name:  "domain",
				Usage: "obtain a certificate for this hostname and serve --dir over TLS; you must point its DNS record at the leased address yourself",
			},
			&cli.BoolFlag{
				Name:  "acme",
				Usage: "obtain a certificate for the hostname the server assigns from its --zone; use instead of --domain when the server names you",
			},
			&cli.BoolFlag{
				Name:  "acme-accept-tos",
				Usage: "accept the certificate authority's subscriber agreement; required with --domain or --acme",
			},
			&cli.StringFlag{
				Name:  "acme-directory",
				Usage: "ACME endpoint (default: Let's Encrypt production). Use the staging URL while debugging — production rate limits are low enough to hit in one afternoon",
			},
			&cli.BoolFlag{
				Name:  "acme-staging",
				Usage: "shorthand for --acme-directory pointing at Let's Encrypt staging; issues untrusted certificates against far looser limits",
			},
			&cli.StringFlag{
				Name:  "acme-cache",
				Usage: "directory for issued certificates and the ACME account key (default: a per-user cache directory). Losing it means re-issuing on every restart",
			},
			&cli.StringFlag{
				Name:  "acme-email",
				Usage: "contact address the CA uses for expiry warnings",
			},
			&cli.StringFlag{
				Name:  "target",
				Value: "127.0.0.1",
				Usage: "host to dial locally",
			},
			&cli.StringFlag{Name: "tls-pin", Usage: "SHA-256 fingerprint of the server certificate to trust"},
			&cli.BoolFlag{Name: "insecure", Usage: "skip server certificate verification entirely; do not use outside a lab"},
			&cli.BoolFlag{Name: "no-wss", Usage: "do not fall back to the WebSocket transport when QUIC fails"},
			&cli.DurationFlag{
				Name:  "retry",
				Value: 5 * time.Second,
				Usage: "how long to wait before reconnecting after the session drops",
			},
		},
		Action: run,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cmd.Run(ctx, os.Args); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "tunnel-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	serveDir := cmd.String("dir")
	dirPort := cmd.Uint("dir-port")
	if dirPort < 1 || dirPort > 65535 {
		return fmt.Errorf("--dir-port %d is not a port number", dirPort)
	}

	// --ports is optional only when --dir supplies one, so an invocation that
	// publishes nothing is refused here rather than connecting and leasing an
	// address that carries no traffic.
	var ports []portspec.Spec
	if decl := cmd.String("ports"); decl != "" {
		var err error
		if ports, err = portspec.Parse(decl); err != nil {
			return err
		}
	} else if serveDir == "" {
		return errors.New("nothing to publish: pass --ports, --dir, or both")
	}

	server := cmd.String("server")
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("--server must be host:port: %w", err)
	}
	tlsConf, err := tlsutil.ClientConfig(host, cmd.String("tls-pin"), cmd.Bool("insecure"))
	if err != nil {
		return err
	}
	if cmd.Bool("insecure") {
		log.Warn("server certificate verification is disabled; anything on the path can impersonate the server")
	}

	acmeConf, err := acmeConfigFrom(cmd)
	if err != nil {
		return err
	}

	httpsBackend, err := httpsBackendFrom(cmd, uint16(dirPort), serveDir)
	if err != nil {
		return err
	}
	if httpsBackend != 0 {
		log.Warn("the server will terminate TLS for this agent, so it can read the plaintext of everything served on 443; forwarded ports stay opaque to it",
			"backend_port", httpsBackend)
	}

	ag, err := agent.New(agent.Config{
		Server:       server,
		Token:        cmd.String("token"),
		Ports:        ports,
		Target:       cmd.String("target"),
		ServeDir:     serveDir,
		ServePort:    uint16(dirPort),
		ACME:         acmeConf,
		HTTPSBackend: httpsBackend,
		Logger:       log,
	})
	if err != nil {
		return err
	}

	dialers := []transport.Dialer{quictp.Dialer{TLSConfig: tlsConf}}
	if !cmd.Bool("no-wss") {
		dialers = append(dialers, wstp.Dialer{TLSConfig: tlsConf})
	}

	retry := cmd.Duration("retry")
	for {
		err := connectOnce(ctx, ag, dialers, server, log)
		var rejected *agent.ErrRejected
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.As(err, &rejected):
			// A rejection is a decision, not a glitch. Retrying it would hammer
			// a server that has already said no, and the reason would scroll
			// past in a loop instead of being the last thing printed.
			return err
		default:
			log.Warn("session ended; reconnecting", "err", err, "in", retry)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retry):
		}
	}
}

// connectOnce tries each transport in turn and runs the first session that
// comes up. QUIC is tried first; the WebSocket fallback exists for networks
// that pass no UDP at all.
func connectOnce(ctx context.Context, ag *agent.Agent, dialers []transport.Dialer, server string, log *slog.Logger) error {
	var lastErr error
	for _, dialer := range dialers {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		sess, err := dialer.Dial(dialCtx, server)
		cancel()
		if err != nil {
			log.Info("transport unavailable", "transport", dialer.Name(), "err", err)
			lastErr = err
			continue
		}
		log.Info("connected", "transport", dialer.Name(), "server", server)
		if dialer.Name() != "quic" {
			log.Warn("running on the fallback transport: tunneled connections share one TCP stream, and tunneled UDP is delivered reliably rather than as sent")
		}
		return ag.Run(ctx, sess)
	}
	if lastErr == nil {
		lastErr = errors.New("no transport available")
	}
	return lastErr
}
