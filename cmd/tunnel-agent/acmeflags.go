package main

import (
	"errors"

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
