package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/xerrors"
)

// Metadata describes where a local version came from, for listing and
// reporting purposes.
type Metadata struct {
	// Origin is "full" or "delta:<base>".
	Origin string `json:"origin"`
	// Base is the version a delta was applied on top of, if any.
	Base string `json:"base,omitempty"`
	// Expected is the digest/identifier the caller expected the resulting
	// version to have. If it does not match, the installation is refused.
	Expected string `json:"expected,omitempty"`
}

// InstallOptions controls installing a version.
type InstallOptions struct {
	// Version optionally overrides the version identifier. By default it is
	// derived from the content digest (see VersionID).
	Version string
	// Origin is recorded in the manifest.
	Origin string
	// Now is used for CreatedAt; defaults to time.Now.
	Now time.Time
}

// VersionID derives a stable version identifier from a database digest.
func VersionID(dbDigest string) string {
	d := strings.TrimPrefix(dbDigest, DigestPrefix)
	if len(d) > 16 {
		d = d[:16]
	}
	return d
}

// InstallFromDir installs a complete database directory produced by an
// external downloader. dir must contain at least trivy.db. The directory is
// hashed, copied into staging, re-verified, and only then moved into place. If
// anything fails, the old active version remains untouched.
//
// This is the "full" path: everything in dir is copied, no matter how it was
// obtained. Use InstallFromStaging when dir already lives under the store's
// staging directory to avoid the copy.
func (s *Store) InstallFromDir(ctx context.Context, dir string, opts InstallOptions) (Manifest, error) {
	m, err := manifestFromDir(dir, opts)
	if err != nil {
		return Manifest{}, err
	}
	return s.install(ctx, dir, m, opts)
}

// InstallFromStaging installs a fully written directory that already lives
// inside the store's staging area. The contents are hashed and verified, then
// the directory is renamed into place under the exclusive lock, so no second
// copy of the database is made. The caller must not reuse dir afterwards.
func (s *Store) InstallFromStaging(ctx context.Context, dir string, opts InstallOptions) (Manifest, error) {
	if !isWithin(filepath.Join(s.root, stagingDir), dir) {
		return Manifest{}, invalid("%s is not inside the store staging directory", dir)
	}
	m, err := manifestFromDir(dir, opts)
	if err != nil {
		return Manifest{}, err
	}
	if err = verifyDir(dir, m); err != nil {
		return Manifest{}, wrapKind(KindIntegrity, err, "staged database failed verification")
	}

	unlock, err := s.acquireExclusive(ctx)
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()

	if err = installStaged(s.root, dir, m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// isWithin reports whether path is dir or below it.
func isWithin(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// InstallDelta applies a delta package on top of baseVersion and installs the
// result. The resulting directory is hashed and compared with the digest
// recorded in the delta header; if they differ (base mismatch, corrupt patch)
// the installation is refused and the active version is unchanged.
func (s *Store) InstallDelta(ctx context.Context, baseVersion string, delta io.Reader, opts InstallOptions) (Manifest, error) {
	base, err := s.Manifest(baseVersion)
	if err != nil {
		if IsKind(err, KindVersionMismatch) {
			return Manifest{}, versionMismatch("delta base version %q is not available locally", baseVersion)
		}
		return Manifest{}, err
	}
	if err = verifyDir(s.versionDir(baseVersion), base); err != nil {
		return Manifest{}, wrapKind(KindIntegrity, err, "delta base version %q failed verification", baseVersion)
	}

	staging, err := s.StagingDir("delta")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(staging) //nolint: errcheck

	if err = applyDelta(s.versionDir(baseVersion), staging, delta, staging); err != nil {
		return Manifest{}, err
	}

	origin := opts.Origin
	if origin == "" {
		origin = "delta:" + baseVersion
	}
	m, err := manifestFromDir(staging, InstallOptions{
		Version: opts.Version,
		Origin:  origin,
		Now:     opts.Now,
	})
	if err != nil {
		return Manifest{}, err
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now()
	}

	// Only the final move needs the write lock: reconstruction of a large
	// database must not block readers of the current version.
	unlock, err := s.acquireExclusive(ctx)
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	if err = installStaged(s.root, staging, m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (s *Store) install(ctx context.Context, srcDir string, m Manifest, _ InstallOptions) (Manifest, error) {
	// Stage the payload without holding the write lock so that a large copy
	// does not block readers of the current version.
	staging, err := s.StagingDir("full")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(staging) //nolint: errcheck

	// Copy the payload into staging so that the caller's directory can be a
	// temp dir that is removed as soon as we return, and so that a re-hash
	// verifies exactly the bytes that will be installed.
	for _, f := range m.Files {
		src := filepath.Join(srcDir, f.Name)
		dst := filepath.Join(staging, f.Name)
		if err = copyFile(src, dst); err != nil {
			return Manifest{}, xerrors.Errorf("failed to stage %s: %w", f.Name, err)
		}
	}
	// Re-verify the staged copy. The source may have changed (or been
	// truncated) between hashing and copying.
	if err = verifyDir(staging, m); err != nil {
		return Manifest{}, wrapKind(KindIntegrity, err,
			"staged database failed verification; refusing to install")
	}

	unlock, err := s.acquireExclusive(ctx)
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()

	if err = installStaged(s.root, staging, m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// manifestFromDir hashes a database directory and builds a manifest. The
// database file must be named trivy.db; metadata.json is included if present.
func manifestFromDir(dir string, opts InstallOptions) (Manifest, error) {
	dbPath := filepath.Join(dir, "trivy.db")
	st, err := os.Stat(dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{}, invalid("the database payload has no trivy.db")
		}
		return Manifest{}, xerrors.Errorf("failed to stat trivy.db: %w", err)
	}
	if !st.Mode().IsRegular() {
		return Manifest{}, invalid("trivy.db is not a regular file")
	}

	var files []File
	names := []string{"trivy.db"}
	if _, err = os.Stat(filepath.Join(dir, metadataFile)); err == nil {
		names = append(names, metadataFile)
	}
	for _, name := range names {
		d, err := DigestFile(filepath.Join(dir, name))
		if err != nil {
			return Manifest{}, err
		}
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return Manifest{}, xerrors.Errorf("failed to stat %s: %w", name, err)
		}
		files = append(files, File{Name: name, Size: info.Size(), Digest: d})
	}
	slices.SortFunc(files, func(a, b File) int { return strings.Compare(a.Name, b.Name) })

	var dbFile File
	for _, f := range files {
		if f.Name == "trivy.db" {
			dbFile = f
		}
	}

	version := opts.Version
	if version == "" {
		version = VersionID(dbFile.Digest)
	}
	if err = checkVersionID(version); err != nil {
		return Manifest{}, err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	m := Manifest{
		Version:       version,
		Format:        layoutVersion,
		SchemaVersion: readSchemaVersion(filepath.Join(dir, metadataFile)),
		DBName:        dbFile.Name,
		DBSize:        dbFile.Size,
		DBDigest:      dbFile.Digest,
		Files:         files,
		Origin:        opts.Origin,
		CreatedAt:     now,
	}
	readTimes(&m, filepath.Join(dir, metadataFile))
	if err = m.validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// installStaged moves a fully-written, verified staging directory into the
// versions directory and writes its manifest. It must be called with the
// exclusive lock held.
func installStaged(root, staging string, m Manifest) error {
	// The staging directory is on the same filesystem as versions/, so the
	// rename is atomic. Write the manifest while the directory is still in
	// staging so that the version is never visible without one.
	if err := writeManifest(staging, m); err != nil {
		return err
	}
	dst := filepath.Join(root, versionsDir, m.Version)
	if _, err := os.Stat(dst); err == nil {
		// An identical version already exists. Re-verify it and reuse it
		// rather than overwriting a directory a reader might be using.
		existing, mErr := readManifest(filepath.Join(dst, manifestFile))
		if mErr == nil && sameContent(existing, m) {
			return nil
		}
		return integrityError(m.DBDigest, existing.DBDigest,
			"version %q already exists with different content; refusing to overwrite", m.Version)
	}
	if err := os.Rename(staging, dst); err != nil {
		return xerrors.Errorf("failed to install version %q: %w", m.Version, err)
	}
	if err := syncDir(filepath.Join(root, versionsDir)); err != nil {
		return err
	}
	return nil
}

// sameContent reports whether two manifests describe identical payloads.
func sameContent(a, b Manifest) bool {
	if a.DBName != b.DBName || a.DBSize != b.DBSize || a.DBDigest != b.DBDigest {
		return false
	}
	if len(a.Files) != len(b.Files) {
		return false
	}
	for i := range a.Files {
		if a.Files[i] != b.Files[i] {
			return false
		}
	}
	return true
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err = out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// metadataJSON mirrors the fields of trivy-db's metadata file that the store
// records in its manifest.
type metadataJSON struct {
	Version      int       `json:"Version"`
	NextUpdate   time.Time `json:"NextUpdate"`
	UpdatedAt    time.Time `json:"UpdatedAt"`
	DownloadedAt time.Time `json:"DownloadedAt"`
}

func readSchemaVersion(path string) int {
	var md metadataJSON
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	if err = json.Unmarshal(b, &md); err != nil {
		return 0
	}
	return md.Version
}

func readTimes(m *Manifest, path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var md metadataJSON
	if err = json.Unmarshal(b, &md); err != nil {
		return
	}
	m.NextUpdate = md.NextUpdate
	m.UpdatedAt = md.UpdatedAt
	m.DownloadedAt = md.DownloadedAt
}

// String renders a manifest for human-readable listings.
func (m Manifest) String() string {
	return fmt.Sprintf("%s (schema %d, %s, %d bytes, created %s)",
		m.Version, m.SchemaVersion, m.DBDigest, m.DBSize, m.CreatedAt.UTC().Format(time.RFC3339))
}
