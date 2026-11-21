// Package dbcommand implements the `trivy db` management commands that
// operate on the versioned local vulnerability database store.
package dbcommand

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db/store"
)

// Options are the inputs shared by the db subcommands.
type Options struct {
	CacheDir string
	Store    db.StoreOptions
	Format   string
	Output   io.Writer
}

func (o Options) stdout() io.Writer {
	if o.Output == nil {
		return os.Stdout
	}
	return o.Output
}

// List prints the retained versions, newest first, marking the active one.
func List(_ context.Context, opts Options) error {
	manifests, err := db.ListManifests(opts.CacheDir, opts.Store)
	if err != nil {
		return err
	}
	active, _ := db.ActiveManifest(opts.CacheDir)

	if opts.Format == "json" {
		type item struct {
			store.Manifest
			Active bool `json:"active"`
		}
		items := make([]item, 0, len(manifests))
		for _, m := range manifests {
			items = append(items, item{Manifest: m, Active: m.Version == active.Version})
		}
		enc := json.NewEncoder(opts.stdout())
		enc.SetIndent("", "  ")
		return enc.Encode(items)
	}

	w := opts.stdout()
	if len(manifests) == 0 {
		fmt.Fprintln(w, "No vulnerability database versions are installed.")
		return nil
	}
	fmt.Fprintf(w, "%-34s %-8s %-14s %-10s %s\n", "VERSION", "SCHEMA", "UPDATED", "ORIGIN", "")
	for _, m := range manifests {
		marker := ""
		if m.Version == active.Version {
			marker = "* active"
		}
		updated := "-"
		if !m.UpdatedAt.IsZero() {
			updated = m.UpdatedAt.UTC().Format("2006-01-02")
		}
		fmt.Fprintf(w, "%-34s %-8d %-14s %-10s %s\n", m.Version, m.SchemaVersion, updated, m.Origin, marker)
	}
	fmt.Fprintln(w, "\nUse --db-version <VERSION> to scan with a specific version.")
	return nil
}

// Activate makes an installed version the active one.
func Activate(ctx context.Context, opts Options, version string) error {
	if err := db.ActivateVersion(ctx, opts.CacheDir, version, opts.Store); err != nil {
		return err
	}
	fmt.Fprintf(opts.stdout(), "Activated vulnerability database version %s\n", version)
	return nil
}

// Rollback switches to the previous version, or to target when specified.
func Rollback(ctx context.Context, opts Options, target string) error {
	version, err := db.Rollback(ctx, opts.CacheDir, target, opts.Store)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.stdout(), "Rolled back to vulnerability database version %s\n", version)
	return nil
}

// Remove deletes a specific installed version.
func Remove(ctx context.Context, opts Options, version string) error {
	if err := db.RemoveVersion(ctx, opts.CacheDir, version, opts.Store); err != nil {
		return err
	}
	fmt.Fprintf(opts.stdout(), "Removed vulnerability database version %s\n", version)
	return nil
}

// ImportOptions controls importing a database from a directory.
type ImportOptions struct {
	Options
	// Dir is a directory containing trivy.db and optionally metadata.json.
	Dir string
	// Activate makes the imported version active.
	Activate bool
	// Version optionally overrides the derived version identifier.
	Version string
}

// Import installs a complete database directory without contacting a registry.
func Import(ctx context.Context, opts ImportOptions) error {
	if opts.Dir == "" {
		return xerrors.New("--input directory is required")
	}
	s, err := db.OpenStore(opts.CacheDir, opts.Store)
	if err != nil {
		return err
	}
	m, err := s.InstallFromDir(ctx, opts.Dir, store.InstallOptions{
		Version: opts.Version,
		Origin:  "import",
		Now:     time.Now(),
	})
	if err != nil {
		return err
	}
	if opts.Activate {
		if err = s.Activate(ctx, m.Version); err != nil {
			return err
		}
	}
	fmt.Fprintf(opts.stdout(), "Imported vulnerability database version %s\n", m.Version)
	return nil
}

// DeltaOptions controls building or installing a delta package.
type DeltaOptions struct {
	Options
	// BaseDir/TargetDir are used by Create.
	BaseDir   string
	TargetDir string
	// DeltaPath is the delta package. It is created by Create and consumed by
	// Apply.
	DeltaPath string
	// Base is the installed base version used by Apply.
	Base string
	// Activate makes the applied version active.
	ActivateVersion bool
}

// CreateDelta writes a delta package between two database directories.
func CreateDelta(_ context.Context, opts DeltaOptions) error {
	if opts.BaseDir == "" || opts.TargetDir == "" {
		return xerrors.New("--base and --target directories are required")
	}
	if opts.DeltaPath == "" {
		return xerrors.New("--output is required")
	}
	f, err := os.Create(opts.DeltaPath)
	if err != nil {
		return xerrors.Errorf("failed to create delta file: %w", err)
	}
	defer f.Close()

	n, err := db.CreateDelta(opts.BaseDir, opts.TargetDir, f)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return xerrors.Errorf("failed to sync delta file: %w", err)
	}
	fmt.Fprintf(opts.stdout(), "Created delta %s (%d bytes) from %s to %s\n",
		opts.DeltaPath, n, opts.BaseDir, opts.TargetDir)
	return nil
}

// ApplyDelta installs a delta package on top of a local base version.
func ApplyDelta(ctx context.Context, opts DeltaOptions) error {
	if opts.DeltaPath == "" {
		return xerrors.New("--delta is required")
	}
	if opts.Base == "" {
		opts.Base = currentVersion(opts.CacheDir)
		if opts.Base == "" {
			return xerrors.New("--base is required when no version is active")
		}
	}
	f, err := os.Open(opts.DeltaPath)
	if err != nil {
		return xerrors.Errorf("failed to open delta file: %w", err)
	}
	defer f.Close()

	version, err := db.InstallDelta(ctx, opts.CacheDir, opts.Base, f, opts.Store)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.stdout(), "Installed vulnerability database version %s from delta\n", version)
	return nil
}

func currentVersion(cacheDir string) string {
	m, ok := db.ActiveManifest(cacheDir)
	if !ok {
		return ""
	}
	return m.Version
}

// ExportOptions controls exporting a local version as a portable archive.
type ExportOptions struct {
	Options
	Version string
	Path    string
}

// Export writes a self-verifying archive of a version. The archive can be
// carried on removable media and imported on an isolated machine, where the
// payload is verified byte for byte before it is installed.
func Export(_ context.Context, opts ExportOptions) error {
	version := opts.Version
	if version == "" {
		version = currentVersion(opts.CacheDir)
	}
	if version == "" {
		return xerrors.New("no version specified and no version is active")
	}
	s, err := db.OpenStore(opts.CacheDir, opts.Store)
	if err != nil {
		return err
	}
	if opts.Path == "" {
		return xerrors.New("--output is required")
	}
	f, err := os.Create(opts.Path)
	if err != nil {
		return xerrors.Errorf("failed to create archive: %w", err)
	}
	defer f.Close()

	if err = s.PackVersion(version, f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return xerrors.Errorf("failed to sync archive: %w", err)
	}
	fmt.Fprintf(opts.stdout(), "Exported vulnerability database version %s to %s\n", version, opts.Path)
	return nil
}

// ImportArchiveOptions controls importing a portable archive.
type ImportArchiveOptions struct {
	Options
	Path     string
	Activate bool
}

// ImportArchive installs a version from a portable archive produced by Export.
func ImportArchive(ctx context.Context, opts ImportArchiveOptions) error {
	if opts.Path == "" {
		return xerrors.New("--input is required")
	}
	f, err := os.Open(opts.Path)
	if err != nil {
		return xerrors.Errorf("failed to open archive: %w", err)
	}
	defer f.Close()

	s, err := db.OpenStore(opts.CacheDir, opts.Store)
	if err != nil {
		return err
	}
	m, err := s.ImportArchive(ctx, f, "import")
	if err != nil {
		return err
	}
	if opts.Activate {
		if err = s.Activate(ctx, m.Version); err != nil {
			return err
		}
	}
	fmt.Fprintf(opts.stdout(), "Imported vulnerability database version %s\n", m.Version)
	return nil
}
