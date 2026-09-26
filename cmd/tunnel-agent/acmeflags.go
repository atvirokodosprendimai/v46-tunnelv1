package main

import (
	"errors"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/agent"
)

// acmeConfigFrom assembles the certificate settings from the flags, refusing
// the combinations that would otherwise fail much later as an opaque ACME
// error.
func acmeConfigFrom(cmd *cli.Command) (agent.ACMEConfig, error) {
	domain := cmd.String("domain")
	useServer := cmd.Bool("acme")

	if domain != "" && useServer {
		return agent.ACMEConfig{}, errors.New("--domain and --acme are alternatives: one names the host yourself, the other asks the server to")
	}

	directory := cmd.String("acme-directory")
	if cmd.Bool("acme-staging") {
		if directory != "" {
			return agent.ACMEConfig{}, errors.New("--acme-staging and --acme-directory both set the endpoint; pass one")
		}
		directory = agent.LetsEncryptStagingDirectory
	}

	return agent.ACMEConfig{
		Domain:            domain,
		UseServerHostname: useServer,
		AcceptTOS:         cmd.Bool("acme-accept-tos"),
		DirectoryURL:      directory,
		CacheDir:          cmd.String("acme-cache"),
		Email:             cmd.String("acme-email"),
	}, nil
}

// httpsBackendFrom resolves which local port the server should forward
// decrypted traffic to, or 0 for no termination.
func httpsBackendFrom(cmd *cli.Command, dirPort uint16, serveDir string) (uint16, error) {
	explicit := cmd.Uint("https-backend")
	shorthand := cmd.Bool("https")

	switch {
	case explicit != 0 && shorthand:
		return 0, errors.New("--https and --https-backend both choose the backend port; pass one")
	case explicit != 0:
		if explicit > 65535 {
			return 0, fmt.Errorf("--https-backend %d is not a port number", explicit)
		}
		return uint16(explicit), nil
	case shorthand:
		if serveDir == "" {
			return 0, errors.New("--https is shorthand for serving --dir over TLS, so it needs --dir; use --https-backend <port> for a local service instead")
		}
		return dirPort, nil
	default:
		return 0, nil
	}
}
