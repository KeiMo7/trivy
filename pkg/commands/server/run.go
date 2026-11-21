package server

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
	rpcServer "github.com/aquasecurity/trivy/pkg/rpc/server"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

// Run runs the scan
func Run(ctx context.Context, opts flag.Options) (err error) {
	log.InitLogger(opts.Debug, opts.Quiet)

	// Set the default HTTP transport
	xhttp.SetDefaultTransport(xhttp.NewTransport(xhttp.Options{
		Insecure: opts.Insecure,
		CACerts:  opts.CACerts,
		Timeout:  opts.Timeout,
	}))

	// configure cache dir
	cacheClient, cleanup, err := cache.New(opts.CacheOpts())
	if err != nil {
		return xerrors.Errorf("server cache error: %w", err)
	}
	defer cleanup()

	// download the database file
	if err = operation.DownloadDBWithOptions(ctx, operation.DBOptions{
		CacheDir:     opts.CacheDir,
		AppVersion:   opts.AppVersion,
		Repositories: opts.DBRepositories,
		Registry:     opts.RegistryOpts(),
		Quiet:        true,
		SkipUpdate:   opts.SkipDBUpdate,
		Store: db.StoreOptions{
			Retention: opts.DBRetention,
			MaxSize:   opts.DBMaxSize,
		},
	}); err != nil {
		return err
	}

	if opts.DownloadDBOnly {
		return nil
	}

	dbDir, release, err := db.Resolve(ctx, opts.CacheDir, "")
	if err != nil {
		return xerrors.Errorf("error in vulnerability DB initialization: %w", err)
	}
	// The server keeps the database open for its whole lifetime and performs
	// its own hot update (closing the database and waiting for in-flight
	// requests first). Holding the store's shared lock here would block the
	// update worker's exclusive lock, so it is dropped after the version has
	// been verified and opened. The server process itself serialises eviction
	// with the update worker's request wait group.
	release()
	if err = db.Init(dbDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialization: %w", err)
	}

	// Initialize WASM modules
	m, err := module.NewManager(ctx, module.Options{
		Dir:            opts.ModuleDir,
		EnabledModules: opts.EnabledModules,
	})
	if err != nil {
		return xerrors.Errorf("WASM module error: %w", err)
	}
	m.Register()

	server := rpcServer.NewServer(opts.AppVersion, opts.Listen, opts.CacheDir, opts.Token, opts.TokenHeader,
		opts.PathPrefix, opts.DBRepositories, opts.RegistryOpts())
	return server.ListenAndServe(ctx, cacheClient, opts.SkipDBUpdate)
}
