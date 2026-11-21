package db

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db/store"
	"github.com/aquasecurity/trivy/pkg/log"
)

// StoreOptions are the retention knobs for the versioned database store.
type StoreOptions struct {
	// Retention is the minimum number of versions kept locally.
	Retention int
	// MaxSize is the soft size limit for retained versions in bytes.
	MaxSize int64
}

// DefaultStoreOptions returns the default retention policy.
func DefaultStoreOptions() StoreOptions {
	return StoreOptions{Retention: store.DefaultOptions().Retention}
}

func (o StoreOptions) toStore() store.Options {
	opts := store.DefaultOptions()
	if o.Retention > 0 {
		opts.Retention = o.Retention
	}
	opts.MaxSize = o.MaxSize
	return opts
}

// StoreDir returns the directory that holds the versioned database store. It
// is the same directory the legacy single-file layout used, so older caches
// and tooling keep working.
func StoreDir(cacheDir string) string {
	return Dir(cacheDir)
}

// OpenStore opens the versioned store for cacheDir.
func OpenStore(cacheDir string, opts StoreOptions) (*store.Store, error) {
	s, err := store.Open(StoreDir(cacheDir), opts.toStore())
	if err != nil {
		return nil, xerrors.Errorf("failed to open database store: %w", err)
	}
	return s, nil
}

// Resolve opens a database directory for scanning.
//
//   - If pin is non-empty, that exact version is verified and used; the active
//     version marker is left untouched so concurrent scans can use different
//     versions.
//   - Otherwise the active version is verified and used.
//   - If the store is empty but a legacy single-file database exists, the
//     legacy directory is used as-is for backward compatibility.
//
// The returned release function must be called after the bbolt database has
// been closed; it drops the shared lock that keeps the version from being
// evicted while a scan is reading it.
func Resolve(ctx context.Context, cacheDir, pin string) (string, func(), error) {
	return ResolveWithOptions(ctx, cacheDir, pin, DefaultStoreOptions())
}

// ResolveWithOptions is Resolve with an explicit retention policy.
func ResolveWithOptions(ctx context.Context, cacheDir, pin string, opts StoreOptions) (string, func(), error) {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return "", nil, err
	}

	var (
		dir     string
		release func()
	)
	if pin != "" {
		m, err := s.Manifest(pin)
		if err != nil {
			return "", nil, err
		}
		dir, release, err = s.OpenVersion(ctx, m.Version)
		if err != nil {
			return "", nil, err
		}
	} else {
		m, _, rel, err := s.OpenActive(ctx)
		if err != nil {
			if legacyDBExists(cacheDir) {
				log.DebugContext(ctx, "Using legacy single-file vulnerability database",
					log.FilePath(Path(Dir(cacheDir))))
				return Dir(cacheDir), func() {}, nil
			}
			return "", nil, xerrors.Errorf("no usable vulnerability database: %w", err)
		}
		dir = filepath.Join(StoreDir(cacheDir), "versions", m.Version)
		release = rel
	}
	return dir, release, nil
}

func legacyDBExists(cacheDir string) bool {
	_, err := os.Stat(Path(Dir(cacheDir)))
	return err == nil
}

// LocalInfo returns the active version's manifest for reporting, or nil if the
// store has no active version.
func LocalInfo(cacheDir string) *store.Manifest {
	s, err := OpenStore(cacheDir, DefaultStoreOptions())
	if err != nil {
		return nil
	}
	m, err := s.Current()
	if err != nil {
		return nil
	}
	return &m
}

// InstallResult is returned after a database has been installed locally.
type InstallResult struct {
	Version string
	Dir     string
}

// InstallFromDir installs a complete database directory into the versioned
// store and activates it. The previous active version remains intact until the
// new one is fully written and verified.
func InstallFromDir(ctx context.Context, cacheDir, srcDir string, opts StoreOptions, origin string) (InstallResult, error) {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return InstallResult{}, err
	}
	m, err := s.InstallFromDir(ctx, srcDir, store.InstallOptions{
		Origin: origin,
		Now:    time.Now(),
	})
	if err != nil {
		return InstallResult{}, err
	}
	if err = s.Activate(ctx, m.Version); err != nil {
		return InstallResult{}, err
	}
	if err = mirrorMetadata(srcDir, StoreDir(cacheDir)); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Version: m.Version, Dir: filepath.Join(StoreDir(cacheDir), "versions", m.Version)}, nil
}

// ActiveManifest returns the active version's manifest if the store manages
// the database.
func ActiveManifest(cacheDir string) (store.Manifest, bool) {
	return ActiveManifestWithOptions(cacheDir, DefaultStoreOptions())
}

// ActiveManifestWithOptions is ActiveManifest with an explicit retention policy.
func ActiveManifestWithOptions(cacheDir string, opts StoreOptions) (store.Manifest, bool) {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return store.Manifest{}, false
	}
	m, err := s.Current()
	if err != nil {
		return store.Manifest{}, false
	}
	return m, true
}

// IsUnavailable reports whether err means that no usable local database exists.
func IsUnavailable(err error) bool {
	return store.IsKind(err, store.KindUnavailable) || store.IsKind(err, store.KindIntegrity)
}

// IsVersionMismatch reports whether err means that the requested version is not
// present locally.
func IsVersionMismatch(err error) bool {
	return store.IsKind(err, store.KindVersionMismatch)
}

// IsRollbackFailed reports whether err means that a rollback could not be
// performed.
func IsRollbackFailed(err error) bool {
	return store.IsKind(err, store.KindRollbackFailed)
}
