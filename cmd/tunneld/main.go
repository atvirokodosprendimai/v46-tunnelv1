// Command tunneld is the tunnel server: it leases an address to each agent and
// publishes the ports that agent declared.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/pool"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/server"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/tlsutil"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/quictp"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/transport/wstp"
)

func main() {
	cmd := &cli.Command{
		Name:  "tunneld",
		Usage: "lease addresses to agents and publish the ports they declare",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "listen",
				Value: ":4443",
				Usage: "address to serve on; QUIC binds the UDP port and the WSS fallback the TCP port of the same number",
			},
			&cli.StringSliceFlag{
				Name:     "pool",
				Usage:    "addresses to lease, as literals or CIDR prefixes (repeatable); they must already exist on this host",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "tokens",
				Usage:    "file of '<token> <agent-name>' lines naming the agents that may connect",
				Required: true,
			},
			&cli.StringFlag{Name: "tls-cert", Usage: "PEM certificate chain"},
			&cli.StringFlag{Name: "tls-key", Usage: "PEM private key"},
			&cli.BoolFlag{
				Name:  "tls-self-signed",
				Usage: "mint a throwaway certificate and print its fingerprint; for development only",
			},
			&cli.StringSliceFlag{
				Name:  "deny-ports",
				Usage: "ports that will never be published (default: 25,465,587,2525 — outbound mail)",
			},
			&cli.BoolFlag{
				Name:  "no-wss",
				Usage: "serve QUIC only, without the WebSocket fallback",
			},
			&cli.BoolFlag{
				Name:  "random-ip",
				Usage: "lease a random free address instead of giving a reconnecting agent the one it had; anything caching a published address will break on reconnect",
			},
			&cli.StringFlag{
				Name:  "zone",
				Usage: "DNS zone to name agents under, e.g. tunnel.example.com; an agent that asks is told <agent>.<zone>. The server assigns the name only — it does not create the DNS record",
			},
		},
		Action: run,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cmd.Run(ctx, os.Args); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "tunneld:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	addrPool, err := pool.New(cmd.StringSlice("pool"), poolMode(cmd.Bool("random-ip")))
	if err != nil {
		return err
	}
	tokens, err := tlsutil.LoadTokens(cmd.String("tokens"))
	if err != nil {
		return err
	}
	denyPorts, err := parseDenyPorts(cmd.StringSlice("deny-ports"))
	if err != nil {
		return err
	}

	tlsConf, err := serverTLS(cmd, log)
	if err != nil {
		return err
	}

	srv, err := server.New(server.Config{
		Pool:      addrPool,
		Auth:      server.StaticTokens(tokens),
		DenyPorts: denyPorts,
		Zone:      cmd.String("zone"),
		Logger:    log,
	})
	if err != nil {
		return err
	}

	listen := cmd.String("listen")
	quicLn, err := quictp.Listen(listen, tlsConf)
	if err != nil {
		return fmt.Errorf("listening for QUIC on %s: %w", listen, err)
	}
	defer quicLn.Close()

	log.Info("listening",
		"quic", quicLn.Addr().String(),
		"pool_size", addrPool.Size(),
		"pool_mode", addrPool.Mode().String(),
		"agents", len(tokens),
		"denied_ports", denyList(denyPorts))

	errs := make(chan error, 2)
	go func() { errs <- srv.Serve(ctx, quicLn) }()

	if !cmd.Bool("no-wss") {
		wsHandler, httpSrv, err := startWSS(ctx, listen, tlsConf, log)
		if err != nil {
			return err
		}
		defer httpSrv.Close()
		go func() { errs <- srv.Serve(ctx, wsHandler) }()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

// startWSS serves the WebSocket fallback on the TCP port matching the QUIC UDP
// port, so an agent configures one address for both transports.
func startWSS(ctx context.Context, listen string, tlsConf *tls.Config, log *slog.Logger) (*wstp.Handler, *http.Server, error) {
	tcpLn, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, nil, fmt.Errorf("listening for WSS on %s: %w", listen, err)
	}
	handler := wstp.NewHandler(tcpLn.Addr())

	mux := http.NewServeMux()
	mux.Handle(wstp.Path, handler)
	// A liveness endpoint an operator can curl without a token. It says the
	// process is up and nothing else, so it needs no authentication.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	httpSrv := &http.Server{
		Handler:   mux,
		TLSConfig: tlsConf.Clone(),
		// A tunnel session lives as long as the agent stays connected, so the
		// usual read and write timeouts would kill every session on schedule.
		// The transports carry their own keepalives instead.
		ReadHeaderTimeout: 20 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	log.Info("wss fallback listening", "addr", tcpLn.Addr().String(), "path", wstp.Path)
	go func() {
		if err := httpSrv.ServeTLS(tcpLn, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("wss listener stopped", "err", err)
		}
	}()
	return handler, httpSrv, nil
}

// serverTLS resolves the server's certificate from the flags.
func serverTLS(cmd *cli.Command, log *slog.Logger) (*tls.Config, error) {
	cert, key := cmd.String("tls-cert"), cmd.String("tls-key")
	selfSigned := cmd.Bool("tls-self-signed")

	switch {
	case selfSigned && (cert != "" || key != ""):
		return nil, errors.New("--tls-self-signed cannot be combined with --tls-cert/--tls-key")
	case selfSigned:
		conf, fingerprint, err := tlsutil.SelfSigned([]string{"localhost", "127.0.0.1", "::1"})
		if err != nil {
			return nil, err
		}
		log.Warn("serving a self-signed certificate; development only",
			"fingerprint", fingerprint,
			"agent_flag", "--tls-pin "+fingerprint)
		return conf, nil
	case cert == "" || key == "":
		return nil, errors.New("a certificate is required: pass --tls-cert and --tls-key, or --tls-self-signed for development")
	default:
		return tlsutil.ServerConfig(cert, key)
	}
}

// parseDenyPorts turns the flag into a port list, returning nil to mean "use
// the default mail block" so an operator who passes nothing still gets it.
func parseDenyPorts(values []string) ([]uint16, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var out []uint16
	for _, v := range values {
		for _, field := range strings.Split(v, ",") {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			n, err := strconv.Atoi(field)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("--deny-ports: %q is not a port number", field)
			}
			out = append(out, uint16(n))
		}
	}
	return out, nil
}

// poolMode turns the --random-ip flag into an allocation mode. Sticky is the
// default because a published address is cached by whatever points at it, so
// changing it on reconnect breaks callers that did nothing wrong.
func poolMode(random bool) pool.Mode {
	if random {
		return pool.Random
	}
	return pool.Sticky
}

// denyList renders the effective deny list for the startup log, so an operator
// can see the mail block is on without having to know the default.
func denyList(ports []uint16) string {
	if ports == nil {
		ports = server.DefaultDenyPorts
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

// ensure the transport interface is satisfied by both listeners at compile time
// rather than at the first connection.
var (
	_ transport.Listener = (*quictp.Listener)(nil)
	_ transport.Listener = (*wstp.Handler)(nil)
)
