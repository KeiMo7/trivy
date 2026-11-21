package db

import (
	"context"
	"io"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db/store"
)

// ErrBaseNotLocal is returned when a delta references a base version that is
// not present in the local store.
var ErrBaseNotLocal = xerrors.New("delta base version is not available locally")

// CreateDelta writes a delta package that transforms the database in baseDir
// into the database in targetDir. Both directories must contain a trivy.db.
func CreateDelta(baseDir, targetDir string, w io.Writer) (int64, error) {
	n, err := store.CreateDelta(baseDir, targetDir, w)
	if err != nil {
		return 0, xerrors.Errorf("failed to create database delta: %w", err)
	}
	return n, nil
}

// InstallDelta applies a delta package on top of baseVersion and activates the
// result. The previous active version is untouched if anything fails.
func InstallDelta(ctx context.Context, cacheDir, baseVersion string, delta io.Reader, opts StoreOptions) (string, error) {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return "", err
	}
	m, err := s.InstallDelta(ctx, baseVersion, delta, store.InstallOptions{Now: time.Now()})
	if err != nil {
		return "", err
	}
	if err = s.Activate(ctx, m.Version); err != nil {
		return "", err
	}
	return m.Version, nil
}

// ActivateVersion switches the active version to an already-installed version.
func ActivateVersion(ctx context.Context, cacheDir, version string, opts StoreOptions) error {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return err
	}
	return s.Activate(ctx, version)
}

// Rollback switches to the previous version, or to target if it is non-empty.
func Rollback(ctx context.Context, cacheDir, target string, opts StoreOptions) (string, error) {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return "", err
	}
	return s.Rollback(ctx, target)
}

// ListManifests returns every retained version, newest first.
func ListManifests(cacheDir string, opts StoreOptions) ([]store.Manifest, error) {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return nil, err
	}
	return s.Versions()
}

// RemoveVersion deletes a specific non-active version.
func RemoveVersion(ctx context.Context, cacheDir, version string, opts StoreOptions) error {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return err
	}
	return s.Remove(ctx, version)
}

// CleanStore removes every retained version.
func CleanStore(ctx context.Context, cacheDir string, opts StoreOptions) error {
	s, err := OpenStore(cacheDir, opts)
	if err != nil {
		return err
	}
	return s.Clean(ctx)
}

// CopyDirToTemp copies the active version's files into a temp directory so a
// delta can be built from it.
func CopyDirToTemp(dir string) (string, func(), error) {
	tmp, err := os.MkdirTemp("", "trivy-db-base-")
	if err != nil {
		return "", nil, xerrors.Errorf("failed to create temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	for _, name := range []string{"trivy.db", "metadata.json"} {
		if err := copyFileIfExists(dir, tmp, name); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return tmp, cleanup, nil
}

func copyFileIfExists(srcDir, dstDir, name string) error {
	src := srcDir + string(os.PathSeparator) + name
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return xerrors.Errorf("failed to stat %s: %w", src, err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return xerrors.Errorf("failed to read %s: %w", src, err)
	}
	if err = os.WriteFile(dstDir+string(os.PathSeparator)+name, b, 0o600); err != nil {
		return xerrors.Errorf("failed to write %s: %w", name, err)
	}
	return nil
}

// MirrorMetadata copies metadata.json from srcDir to dstDir. It keeps a
// metadata.json at the store root for tools that expect the legacy layout.
// The metadata file is informational; the authoritative copy lives inside the
// version directory.
func MirrorMetadata(srcDir, dstDir string) error {
	return mirrorMetadata(srcDir, dstDir)
}

// mirrorMetadata keeps a metadata.json copy at the store root for backward
// compatibility with tools (and older Trivy releases) that read it there. It is
// a small file; the database itself exists only inside its version directory.
func mirrorMetadata(srcDir, dstDir string) error {
	src := srcDir + string(os.PathSeparator) + "metadata.json"
	data, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return xerrors.Errorf("failed to read metadata for compatibility copy: %w", err)
	}
	dst := dstDir + string(os.PathSeparator) + "metadata.json"
	if err = os.WriteFile(dst, data, 0o600); err != nil {
		return xerrors.Errorf("failed to write compatibility metadata: %w", err)
	}
	return nil
}
