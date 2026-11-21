package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/xerrors"
)

const (
	layoutVersion = 1
	manifestFile  = "manifest.json"
	// metadataFile is the trivy-db metadata file name kept inside each
	// version directory so that existing tooling can keep reading it.
	metadataFile = "metadata.json"
	// lockFile serialises writers (install/rollback/gc) against readers.
	lockFile = ".lock"
)

// Manifest describes one locally retained database version.
//
// Manifest is the source of truth for "is this version usable": a version with
// a manifest is only served after the referenced files verify against the
// recorded size and digest. The manifest itself is written last and atomically
// (temp file + rename + directory fsync), so a partially transferred or
// partially reconstructed version is never visible.
type Manifest struct {
	// Version is the content version identifier (e.g. an OCI digest or a
	// build identifier). It is used in paths and on the command line, so it
	// must be a safe path segment.
	Version string `json:"version"`

	// Format is the layout version of this manifest.
	Format int `json:"format"`

	// SchemaVersion is the trivy-db schema version the payload was built for.
	SchemaVersion int `json:"schema_version"`

	// DBName/DBSize/DBDigest describe the primary database file.
	DBName   string `json:"db_name"`
	DBSize   int64  `json:"db_size"`
	DBDigest string `json:"db_digest"`

	// Files lists every file of the version with its size and digest.
	Files []File `json:"files"`

	// UpdatedAt/NextUpdate/DownloadedAt are copied from the DB metadata for
	// reporting and for compatibility with the legacy layout.
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
	NextUpdate   time.Time `json:"next_update,omitempty"`
	DownloadedAt time.Time `json:"downloaded_at,omitempty"`

	// Origin records where the version came from ("full", "delta:<base>",
	// "import") purely for operators reading `db list`.
	Origin string `json:"origin,omitempty"`

	// CreatedAt is when this version was activated locally.
	CreatedAt time.Time `json:"created_at"`
}

// File is a single checked file inside a version.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// file returns the named file entry.
func (m Manifest) file(name string) (File, bool) {
	files := sortedFiles(m.Files)
	i, found := slices.BinarySearchFunc(files, name, func(f File, name string) int {
		return strings.Compare(f.Name, name)
	})
	if !found {
		return File{}, false
	}
	return files[i], true
}

func sortedFiles(files []File) []File {
	out := slices.Clone(files)
	slices.SortFunc(out, func(a, b File) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// validate performs the structural checks that must hold before a manifest is
// trusted at all.
func (m Manifest) validate() error {
	if m.Format != layoutVersion {
		return integrityError("", "", "unsupported manifest format %d", m.Format)
	}
	if m.Version == "" || filepath.Base(m.Version) != m.Version || m.Version == "." || m.Version == ".." {
		return integrityError("", "", "invalid version identifier %q", m.Version)
	}
	if m.DBName == "" {
		return integrityError("", "", "manifest of version %q has no database file", m.Version)
	}
	var found bool
	for _, f := range m.Files {
		if filepath.Base(f.Name) != f.Name {
			return integrityError("", "", "manifest of version %q references unsafe file %q", m.Version, f.Name)
		}
		if f.Name == m.DBName {
			found = true
			if f.Size != m.DBSize || f.Digest != m.DBDigest {
				return integrityError("", "", "manifest of version %q is inconsistent about the database file", m.Version)
			}
		}
	}
	if !found {
		return integrityError("", "", "manifest of version %q does not list its database file", m.Version)
	}
	return nil
}

func readManifest(path string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, xerrors.Errorf("failed to read %s: %w", path, err)
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return Manifest{}, integrityError("", "", "failed to decode %s: %v", path, err)
	}
	if err = m.validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// writeManifest writes the manifest atomically: encode to a temp file in the
// same directory, fsync it, rename over the target, then fsync the directory.
// Readers either see the old manifest or the new one, never a partial one.
func writeManifest(dir string, m Manifest) error {
	if err := m.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to encode manifest: %w", err)
	}
	b = append(b, '\n')

	tmp, err := os.CreateTemp(dir, ".manifest-*")
	if err != nil {
		return xerrors.Errorf("failed to create temp manifest: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint: errcheck

	if _, err = tmp.Write(b); err != nil {
		_ = tmp.Close()
		return xerrors.Errorf("failed to write manifest: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return xerrors.Errorf("failed to sync manifest: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return xerrors.Errorf("failed to close manifest: %w", err)
	}
	if err = os.Rename(tmpName, filepath.Join(dir, manifestFile)); err != nil {
		return xerrors.Errorf("failed to activate manifest: %w", err)
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so that a preceding rename survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return xerrors.Errorf("failed to open directory %s: %w", dir, err)
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return xerrors.Errorf("failed to sync directory %s: %w", dir, err)
	}
	return nil
}

// writeFileAtomic writes data to path via a temp file + rename in the same
// directory, fsyncing both the file and the directory.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return xerrors.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint: errcheck

	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return xerrors.Errorf("failed to write temp file: %w", err)
	}
	if err = tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return xerrors.Errorf("failed to chmod temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return xerrors.Errorf("failed to sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return xerrors.Errorf("failed to close temp file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return xerrors.Errorf("failed to rename temp file: %w", err)
	}
	return syncDir(dir)
}
