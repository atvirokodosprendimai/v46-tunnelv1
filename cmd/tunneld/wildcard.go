package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/server"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/subdomain"
	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/wildcard"
)

// certsOrNil converts a possibly-nil manager into the interface the server
// takes.
//
// A typed nil in an interface is not nil, so assigning the manager directly
// would give the server a non-nil CertificateSource whose every call panics.
// This is the one place that conversion happens, so it is the one place the
// mistake can be made.
func certsOrNil(m *wildcard.Manager) server.CertificateSource {
	if m == nil {
		return nil
	}
	return m
}

// startWildcard brings up the wildcard certificate manager, or returns nil when
// no certificate was asked for.
//
// It does not block on issuance. The first order takes tens of seconds and may
// fail — the zone may not be delegated yet — and holding the whole server on
// that would stop every non-TLS tunnel from working for a reason that has
// nothing to do with them.
func startWildcard(ctx context.Context, cmd *cli.Command, registry *subdomain.Registry, log *slog.Logger) (*wildcard.Manager, error) {
	if !cmd.Bool("wildcard-cert") {
		return nil, nil
	}
	if registry == nil {
		return nil, errors.New("--wildcard-cert needs --domain: the certificate covers the zone's subdomains")
	}

	cacheDir := cmd.String("acme-cache")
	if cacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil, errors.New("no cache directory available; pass --acme-cache")
		}
		cacheDir = filepath.Join(base, "v46-tunneld", "acme")
	}

	directory := cmd.String("acme-directory")
	if cmd.Bool("acme-staging") {
		if directory != "" {
			return nil, errors.New("--acme-staging and --acme-directory both set the endpoint; pass one")
		}
		directory = wildcard.LetsEncryptStagingDirectory
	}

	mgr, err := wildcard.New(wildcard.Config{
		Domain:       registry.Zone(),
		Registry:     registry,
		CacheDir:     cacheDir,
		DirectoryURL: directory,
		Email:        cmd.String("acme-email"),
		AcceptTOS:    cmd.Bool("acme-accept-tos"),
		Logger:       log,
	})
	if err != nil {
		return nil, err
	}

	go func() {
		if err := mgr.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("wildcard certificate manager stopped", "err", err)
		}
	}()
	log.Info("wildcard certificate manager started",
		"names", []string{"*." + registry.Zone(), registry.Zone()},
		"cache", cacheDir,
		"ready", mgr.Ready())
	return mgr, nil
}
