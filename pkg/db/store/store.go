// Package store implements a versioned, integrity-checked local store for the
// vulnerability database.
//
// The store keeps multiple complete versions side by side. Each version is a
// directory containing the database files plus a manifest with size and sha256
// digests. A version only becomes visible after its manifest has been written
// atomically, so an interrupted transfer can never leave a half-written
// database in place of a usable one.
//
// Layout under the store root:
//
//	<root>/
//	  .lock                     advisory lock file
//	  versions/
//	    <version>/              one complete, verified version
//	      trivy.db
//	      metadata.json
//	      manifest.json
//	  current                   text file: version id of the active version
//	  staging/                  in-progress transfers (never read by scans)
package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	versionsDir = "versions"
	stagingDir  = "staging"
	currentFile = "current"
)

// Options configures a Store.
type Options struct {
	// MaxSize is the soft upper bound for the versions directory. When it is
	// exceeded, Retention versions are kept and the oldest remaining versions
	// are evicted, oldest first, until the store fits. Zero means unlimited.
	MaxSize int64
	// Retention is the minimum number of versions to keep regardless of size.
	// It defaults to 2 (the active version and one rollback target).
	Retention int
}

// DefaultOptions returns the default retention policy.
func DefaultOptions() Options {
	return Options{Retention: 2}
}

// Store manages versioned vulnerability databases.
type Store struct {
	root string
	opts Options
}

// Open opens (creating if needed) a store rooted at root.
func Open(root string, opts Options) (*Store, error) {
	if opts.Retention < 1 {
		opts.Retention = 1
	}
	if err := os.MkdirAll(filepath.Join(root, versionsDir), 0o700); err != nil {
		return nil, xerrors.Errorf("failed to create database store: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, stagingDir), 0o700); err != nil {
		return nil, xerrors.Errorf("failed to create staging directory: %w", err)
	}
	return &Store{root: root, opts: opts}, nil
}

// Root returns the store root directory.
func (s *Store) Root() string { return s.root }

func (s *Store) versionDir(version string) string {
	return filepath.Join(s.root, versionsDir, version)
}

func (s *Store) currentPath() string {
	return filepath.Join(s.root, currentFile)
}

// Versions lists all locally retained versions, newest first by activation
// time. Directories without a valid manifest are ignored (they were never
// activated).
func (s *Store) Versions() ([]Manifest, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, versionsDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, xerrors.Errorf("failed to list versions: %w", err)
	}
	var manifests []Manifest
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := readManifest(filepath.Join(s.versionDir(e.Name()), manifestFile))
		if err != nil {
			log.Debug("Ignoring version without a valid manifest",
				log.String("version", e.Name()), log.Err(err))
			continue
		}
		manifests = append(manifests, m)
	}
	sort.Slice(manifests, func(i, j int) bool {
		if manifests[i].CreatedAt.Equal(manifests[j].CreatedAt) {
			return manifests[i].Version > manifests[j].Version
		}
		return manifests[i].CreatedAt.After(manifests[j].CreatedAt)
	})
	return manifests, nil
}

// Current returns the manifest of the active version.
func (s *Store) Current() (Manifest, error) {
	b, err := os.ReadFile(s.currentPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{}, unavailable("no vulnerability database version is active")
		}
		return Manifest{}, wrapKind(KindUnavailable, err, "failed to read the active version")
	}
	version := strings.TrimSpace(string(b))
	if version == "" {
		return Manifest{}, unavailable("the active version marker is empty")
	}
	m, err := readManifest(filepath.Join(s.versionDir(version), manifestFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{}, unavailable("the active version %q is missing", version)
		}
		return Manifest{}, err
	}
	return m, nil
}

// Manifest returns the manifest of a specific local version.
func (s *Store) Manifest(version string) (Manifest, error) {
	if err := checkVersionID(version); err != nil {
		return Manifest{}, err
	}
	m, err := readManifest(filepath.Join(s.versionDir(version), manifestFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{}, versionMismatch("version %q is not available locally", version)
		}
		return Manifest{}, err
	}
	return m, nil
}

// DBPath returns the path to the database file of a version.
func (s *Store) DBPath(version string) (string, error) {
	m, err := s.Manifest(version)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.versionDir(version), m.DBName), nil
}

// OpenActive verifies and opens the active version for scanning. It returns a
// manifest and a release function. The returned database path is guaranteed to
// verify against the manifest at the time it is returned, and the shared lock
// held by the caller prevents a concurrent GC from removing it.
func (s *Store) OpenActive(ctx context.Context) (Manifest, string, func(), error) {
	unlock, err := s.acquireShared(ctx)
	if err != nil {
		return Manifest{}, "", nil, err
	}
	release := func() { unlock() }

	m, err := s.Current()
	if err != nil {
		release()
		return Manifest{}, "", nil, err
	}
	dir := s.versionDir(m.Version)
	if err = verifyDir(dir, m); err != nil {
		release()
		return Manifest{}, "", nil, wrapKind(KindUnavailable, err,
			"the active version %q failed integrity verification", m.Version)
	}
	return m, filepath.Join(dir, m.DBName), release, nil
}

// OpenVersion verifies and opens a specific local version for scanning,
// without changing the active version. It is used for pinned scans.
func (s *Store) OpenVersion(ctx context.Context, version string) (string, func(), error) {
	unlock, err := s.acquireShared(ctx)
	if err != nil {
		return "", nil, err
	}
	release := func() { unlock() }

	m, err := s.Manifest(version)
	if err != nil {
		release()
		return "", nil, err
	}
	dir := s.versionDir(version)
	if err = verifyDir(dir, m); err != nil {
		release()
		return "", nil, wrapKind(KindUnavailable, err,
			"version %q failed integrity verification", version)
	}
	return dir, release, nil
}

// CurrentVersion returns the active version identifier, or "" if none.
func (s *Store) CurrentVersion() string {
	m, err := s.Current()
	if err != nil {
		return ""
	}
	return m.Version
}

// Activate atomically makes version the active version. The version must
// already exist locally and verify. Activation is a single rename of the
// "current" marker, so concurrent readers observe either the old or the new
// version, never a mix.
func (s *Store) Activate(ctx context.Context, version string) error {
	unlock, err := s.acquireExclusive(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	if err = s.activate(version); err != nil {
		return err
	}
	return s.gcLocked(ctx)
}

func (s *Store) activate(version string) error {
	if err := checkVersionID(version); err != nil {
		return err
	}
	m, err := readManifest(filepath.Join(s.versionDir(version), manifestFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return versionMismatch("version %q is not available locally", version)
		}
		return err
	}
	if err = verifyDir(s.versionDir(version), m); err != nil {
		return wrapKind(KindIntegrity, err, "version %q cannot be activated because it failed verification", version)
	}
	if err = writeFileAtomic(s.currentPath(), []byte(version+"\n"), 0o600); err != nil {
		return xerrors.Errorf("failed to activate version %q: %w", version, err)
	}
	log.Info("Activated vulnerability database version", log.String("version", version))
	return nil
}

// Rollback switches to the most recent version older than the active one. If
// target is non-empty, it switches to that exact version instead. Rolling back
// to a version that has been evicted is an explicit failure.
func (s *Store) Rollback(ctx context.Context, target string) (string, error) {
	unlock, err := s.acquireExclusive(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()

	current := s.CurrentVersion()
	if current == "" {
		return "", unavailable("no vulnerability database version is active; there is nothing to roll back from")
	}

	if target == "" {
		versions, err := s.Versions()
		if err != nil {
			return "", err
		}
		// Versions are newest first. The previous version is the next entry
		// after the active one in that order.
		idx := -1
		for i, m := range versions {
			if m.Version == current {
				idx = i
				break
			}
		}
		if idx < 0 || idx+1 >= len(versions) {
			return "", rollbackFailed("no previous version is available to roll back to")
		}
		target = versions[idx+1].Version
	}

	if target == current {
		return "", rollbackFailed("version %q is already active", target)
	}
	if _, err = s.Manifest(target); err != nil {
		if IsKind(err, KindVersionMismatch) {
			return "", rollbackFailed("rollback target %q has been evicted and cannot be restored", target)
		}
		return "", err
	}
	if err = s.activate(target); err != nil {
		if IsKind(err, KindIntegrity) {
			return "", rollbackFailed("rollback target %q failed integrity verification; refusing to roll back", target)
		}
		return "", err
	}
	return target, nil
}

// Remove deletes a specific version from the store. The active version cannot
// be removed.
func (s *Store) Remove(ctx context.Context, version string) error {
	unlock, err := s.acquireExclusive(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	if err = checkVersionID(version); err != nil {
		return err
	}
	if s.CurrentVersion() == version {
		return invalid("refusing to remove the active version %q", version)
	}
	if _, err = s.Manifest(version); err != nil {
		return err
	}
	if err = os.RemoveAll(s.versionDir(version)); err != nil {
		return xerrors.Errorf("failed to remove version %q: %w", version, err)
	}
	return nil
}

// Clean removes every version and the active marker.
func (s *Store) Clean(ctx context.Context) error {
	unlock, err := s.acquireExclusive(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err = os.RemoveAll(filepath.Join(s.root, versionsDir)); err != nil {
		return xerrors.Errorf("failed to remove versions: %w", err)
	}
	_ = os.Remove(s.currentPath())
	_ = os.RemoveAll(filepath.Join(s.root, stagingDir))
	if err = os.MkdirAll(filepath.Join(s.root, versionsDir), 0o700); err != nil {
		return xerrors.Errorf("failed to recreate versions directory: %w", err)
	}
	return nil
}

// gcLocked applies the retention policy. It must be called with the exclusive
// lock held. The active version and the most recent Retention versions are
// always kept; older versions are evicted oldest first, and size pressure
// never evicts below Retention versions.
func (s *Store) gcLocked(_ context.Context) error {
	versions, err := s.Versions()
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return nil
	}
	current := s.CurrentVersion()

	keep := map[string]bool{}
	if current != "" {
		keep[current] = true
	}
	for i, m := range versions {
		if i < s.opts.Retention {
			keep[m.Version] = true
		}
	}

	// Oldest first for eviction.
	evictable := make([]Manifest, 0, len(versions))
	for _, m := range versions {
		if !keep[m.Version] {
			evictable = append(evictable, m)
		}
	}
	sort.Slice(evictable, func(i, j int) bool {
		return evictable[i].CreatedAt.Before(evictable[j].CreatedAt)
	})

	if s.opts.MaxSize > 0 {
		total, err := s.versionsSize()
		if err != nil {
			return err
		}
		for _, m := range evictable {
			if total <= s.opts.MaxSize {
				break
			}
			size, err := dirSize(s.versionDir(m.Version))
			if err != nil {
				return err
			}
			if err = s.evict(m.Version); err != nil {
				return err
			}
			total -= size
		}
		// Anything still over the limit has already been reduced to the
		// protected set.
		if total > s.opts.MaxSize {
			log.Warn("Vulnerability database store exceeds the configured maximum size; "+
				"retention policy prevents further eviction",
				log.Int64("size", total), log.Int64("max_size", s.opts.MaxSize))
		}
		return nil
	}

	// With no size limit, retain only the policy-mandated versions.
	for _, m := range evictable {
		if err = s.evict(m.Version); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) evict(version string) error {
	log.Info("Evicting vulnerability database version", log.String("version", version))
	if err := os.RemoveAll(s.versionDir(version)); err != nil {
		return xerrors.Errorf("failed to evict version %q: %w", version, err)
	}
	return nil
}

// versionsSize returns the total size of the versions directory.
func (s *Store) versionsSize() (int64, error) {
	return dirSize(filepath.Join(s.root, versionsDir))
}

// StagingDir creates a fresh staging directory for an in-progress transfer.
// The caller must remove it when done; it is never served to scans.
func (s *Store) StagingDir(prefix string) (string, error) {
	dir, err := os.MkdirTemp(filepath.Join(s.root, stagingDir), prefix+"-")
	if err != nil {
		return "", xerrors.Errorf("failed to create staging directory: %w", err)
	}
	return dir, nil
}

// checkVersionID rejects identifiers that would escape the versions directory.
func checkVersionID(version string) error {
	if version == "" {
		return invalid("empty version identifier")
	}
	if filepath.Base(version) != version || version == "." || version == ".." ||
		strings.ContainsAny(version, `/\`) {
		return invalid("invalid version identifier %q", version)
	}
	return nil
}

func (s *Store) acquireExclusive(ctx context.Context) (func(), error) {
	l, err := newLock(s.root)
	if err != nil {
		return nil, err
	}
	return l.exclusive(ctx)
}

func (s *Store) acquireShared(ctx context.Context) (func(), error) {
	l, err := newLock(s.root)
	if err != nil {
		return nil, err
	}
	return l.shared(ctx)
}
