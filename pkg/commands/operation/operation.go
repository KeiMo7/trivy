package operation

import (
	"context"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
	"github.com/aquasecurity/trivy/pkg/vex/repo"
)

var mu sync.Mutex

// DBOptions collects the DB-related options required to update and use the
// versioned database store.
type DBOptions struct {
	CacheDir     string
	AppVersion   string
	Repositories []name.Reference
	Registry     ftypes.RegistryOptions
	Quiet        bool
	SkipUpdate   bool

	// Pin selects a specific installed version for this scan. The active
	// version marker is not changed.
	Pin string

	Store db.StoreOptions
}

// DownloadDB downloads the DB using the default store options.
func DownloadDB(ctx context.Context, appVersion, cacheDir string, dbRepositories []name.Reference, quiet, skipUpdate bool,
	opt ftypes.RegistryOptions) error {
	return DownloadDBWithOptions(ctx, DBOptions{
		CacheDir:     cacheDir,
		AppVersion:   appVersion,
		Repositories: dbRepositories,
		Registry:     opt,
		Quiet:        quiet,
		SkipUpdate:   skipUpdate,
	})
}

// DownloadDBWithOptions makes sure a verified database version is available.
// When an update is needed it is installed and activated atomically; when it is
// not, the existing active version is left untouched.
func DownloadDBWithOptions(ctx context.Context, opts DBOptions) error {
	mu.Lock()
	defer mu.Unlock()

	ctx = log.WithContextPrefix(ctx, log.PrefixVulnerabilityDB)
	dbDir := db.Dir(opts.CacheDir)
	client := db.NewClient(dbDir, opts.Quiet,
		db.WithDBRepository(opts.Repositories),
		db.WithStoreOptions(opts.Store))

	needsUpdate, err := client.NeedsUpdate(ctx, opts.AppVersion, opts.SkipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.InfoContext(ctx, "Need to update DB")
		if err = client.Download(ctx, dbDir, opts.Registry); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
	}

	// for debug
	if err = client.ShowInfo(); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

func DownloadVEXRepositories(ctx context.Context, opts flag.Options) error {
	ctx = log.WithContextPrefix(ctx, "vex")
	if opts.SkipVEXRepoUpdate {
		log.InfoContext(ctx, "Skipping VEX repository update")
		return nil
	}

	mu.Lock()
	defer mu.Unlock()

	// Download VEX repositories only if `--vex repo` is passed.
	_, enabled := lo.Find(opts.VEXSources, func(src vex.Source) bool {
		return src.Type == vex.TypeRepository
	})
	if !enabled {
		return nil
	}

	err := repo.NewManager(opts.CacheDir).DownloadRepositories(ctx, nil, repo.Options{
		Insecure: opts.Insecure,
	})
	if err != nil {
		return xerrors.Errorf("failed to download vex repositories: %w", err)
	}

	return nil

}

// InitBuiltinChecks downloads the built-in policies and loads them
func InitBuiltinChecks(ctx context.Context, client *policy.Client, skipUpdate bool, registryOpts ftypes.RegistryOptions) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	ctx = log.WithContextPrefix(ctx, "checks-client")

	var err error

	if skipUpdate {
		log.InfoContext(ctx, "No downloadable checks were loaded as --skip-check-update is enabled, loading from existing cache...")

		path := client.BuiltinChecksPath()
		_, _, err := misconf.CheckPathExists(path)
		if err != nil {
			return "", xerrors.Errorf("failed to check cache: %w", err)
		}
		return path, nil
	}

	needsUpdate, err := client.NeedsUpdate(ctx, registryOpts)
	if err != nil {
		return "", xerrors.Errorf("unable to check if built-in policies need to be updated: %w", err)
	}

	if needsUpdate {
		log.InfoContext(ctx, "Need to update the checks bundle")
		log.InfoContext(ctx, "Downloading the checks bundle...")
		if err = client.DownloadBuiltinChecks(ctx, registryOpts); err != nil {
			return "", xerrors.Errorf("failed to download checks bundle: %w", err)
		}
	} else {
		log.InfoContext(ctx,
			"Using existing checks from cache",
			log.String("path", client.BuiltinChecksPath()),
		)
	}

	return client.BuiltinChecksPath(), nil
}

func Exit(opts flag.Options, failedResults bool, m types.Metadata) error {
	if opts.ExitOnEOL != 0 && m.OS != nil && m.OS.Eosl {
		log.Error("Detected EOL OS", log.String("family", string(m.OS.Family)),
			log.String("version", m.OS.Name))
		return &types.ExitError{Code: opts.ExitOnEOL}
	}

	if opts.ExitCode != 0 && failedResults {
		return &types.ExitError{Code: opts.ExitCode}
	}
	return nil
}
