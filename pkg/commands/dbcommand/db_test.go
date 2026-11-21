package dbcommand_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/commands/dbcommand"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db/store"
)

func makeDBDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy.db"), []byte(content), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"),
		[]byte(`{"Version":2,"NextUpdate":"3000-01-01T00:00:00Z","UpdatedAt":"2026-01-01T00:00:00Z"}`), 0o600))
	return dir
}

func opts(cacheDir string, w *bytes.Buffer) dbcommand.Options {
	return dbcommand.Options{
		CacheDir: cacheDir,
		Store:    db.DefaultStoreOptions(),
		Output:   w,
	}
}

func TestImportListActivate(t *testing.T) {
	ctx := t.Context()
	cacheDir := t.TempDir()
	var out bytes.Buffer

	require.NoError(t, dbcommand.Import(ctx, dbcommand.ImportOptions{
		Options:  opts(cacheDir, &out),
		Dir:      makeDBDir(t, "version-one"),
		Activate: true,
		Version:  "v1",
	}))
	require.NoError(t, dbcommand.Import(ctx, dbcommand.ImportOptions{
		Options:  opts(cacheDir, &out),
		Dir:      makeDBDir(t, "version-two"),
		Activate: true,
		Version:  "v2",
	}))

	out.Reset()
	require.NoError(t, dbcommand.List(ctx, opts(cacheDir, &out)))
	assert.Contains(t, out.String(), "v1")
	assert.Contains(t, out.String(), "v2")
	assert.Contains(t, out.String(), "* active")

	// JSON listing marks exactly one active version.
	out.Reset()
	listOpts := opts(cacheDir, &out)
	listOpts.Format = "json"
	require.NoError(t, dbcommand.List(ctx, listOpts))
	var items []struct {
		Version string `json:"version"`
		Active  bool   `json:"active"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &items))
	require.Len(t, items, 2)
	active := 0
	for _, it := range items {
		if it.Active {
			active++
			assert.Equal(t, "v2", it.Version)
		}
	}
	assert.Equal(t, 1, active)
}

func TestRollback(t *testing.T) {
	ctx := t.Context()
	cacheDir := t.TempDir()
	var out bytes.Buffer

	for _, v := range []string{"v1", "v2"} {
		require.NoError(t, dbcommand.Import(ctx, dbcommand.ImportOptions{
			Options:  opts(cacheDir, &out),
			Dir:      makeDBDir(t, v+"-content"),
			Activate: true,
			Version:  v,
		}))
	}

	out.Reset()
	require.NoError(t, dbcommand.Rollback(ctx, opts(cacheDir, &out), ""))
	m, ok := db.ActiveManifest(cacheDir)
	require.True(t, ok)
	assert.Equal(t, "v1", m.Version)

	// Rolling back to a nonexistent target fails as rollback_failed.
	err := dbcommand.Rollback(ctx, opts(cacheDir, &out), "missing")
	require.Error(t, err)
	assert.True(t, db.IsRollbackFailed(err), "got %#v", err)
}

func TestExportImportArchive(t *testing.T) {
	ctx := t.Context()
	src := t.TempDir()
	var out bytes.Buffer

	require.NoError(t, dbcommand.Import(ctx, dbcommand.ImportOptions{
		Options:  opts(src, &out),
		Dir:      makeDBDir(t, "portable-content"),
		Activate: true,
		Version:  "portable",
	}))

	archive := filepath.Join(t.TempDir(), "db.tar.gz")
	require.NoError(t, dbcommand.Export(ctx, dbcommand.ExportOptions{
		Options: opts(src, &out),
		Version: "portable",
		Path:    archive,
	}))

	dst := t.TempDir()
	require.NoError(t, dbcommand.ImportArchive(ctx, dbcommand.ImportArchiveOptions{
		Options:  opts(dst, &out),
		Path:     archive,
		Activate: true,
	}))

	orig, err := os.ReadFile(filepath.Join(src, "db", "versions", "portable", "trivy.db"))
	require.NoError(t, err)
	copied, err := os.ReadFile(filepath.Join(dst, "db", "versions", "portable", "trivy.db"))
	require.NoError(t, err)
	assert.Equal(t, orig, copied)
}

func TestImportRequiresInput(t *testing.T) {
	err := dbcommand.Import(t.Context(), dbcommand.ImportOptions{Options: opts(t.TempDir(), &bytes.Buffer{})})
	require.Error(t, err)
}

func TestDeltaCreateAndApply(t *testing.T) {
	ctx := t.Context()
	cacheDir := t.TempDir()
	var out bytes.Buffer

	baseDir := makeDBDir(t, "base-content")
	var target bytes.Buffer
	target.WriteString("base-content-plus-more")

	targetDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "trivy.db"), target.Bytes(), 0o600))

	deltaPath := filepath.Join(t.TempDir(), "d.delta")
	require.NoError(t, dbcommand.CreateDelta(ctx, dbcommand.DeltaOptions{
		Options:   opts(cacheDir, &out),
		BaseDir:   baseDir,
		TargetDir: targetDir,
		DeltaPath: deltaPath,
	}))

	require.NoError(t, dbcommand.Import(ctx, dbcommand.ImportOptions{
		Options:  opts(cacheDir, &out),
		Dir:      baseDir,
		Activate: true,
		Version:  "base",
	}))

	require.NoError(t, dbcommand.ApplyDelta(ctx, dbcommand.DeltaOptions{
		Options:   opts(cacheDir, &out),
		Base:      "base",
		DeltaPath: deltaPath,
	}))

	m, ok := db.ActiveManifest(cacheDir)
	require.True(t, ok)
	assert.NotEqual(t, "base", m.Version)
	got, err := os.ReadFile(filepath.Join(cacheDir, "db", "versions", m.Version, "trivy.db"))
	require.NoError(t, err)
	assert.Equal(t, target.Bytes(), got)
}

func TestExitCodeMapping(t *testing.T) {
	tests := []struct {
		err  error
		code int
	}{
		{store.Unavailable("x"), store.ExitUnavailable},
		{store.VersionMismatch("x"), store.ExitVersionMismatch},
		{store.RollbackFailed("x"), store.ExitRollbackFailed},
	}
	for _, tt := range tests {
		var coder interface{ ExitCode() int }
		require.ErrorAs(t, tt.err, &coder)
		assert.Equal(t, tt.code, coder.ExitCode())
	}
}
