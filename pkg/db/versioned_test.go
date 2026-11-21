package db_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db/store"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
)

// TestClient_Download_VersionedStore verifies that downloading into the store
// directory installs and activates a verified version, without leaving a
// half-written database in the store.
func TestClient_Download_VersionedStore(t *testing.T) {
	ctx := clock.With(t.Context(), time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC))

	art := dbtest.NewFakeDB(t, "testdata/db.tar.gz", dbtest.FakeDBOptions{})
	cacheDir := t.TempDir()
	dbDir := db.Dir(cacheDir)
	client := db.NewClient(dbDir, true, db.WithOCIArtifact(art))

	require.NoError(t, client.Download(ctx, dbDir, ftypes.RegistryOptions{}))

	m, ok := db.ActiveManifest(cacheDir)
	require.True(t, ok)
	assert.NotEmpty(t, m.Version)
	// The fake artifact carries its own metadata schema version.
	assert.Equal(t, 1, m.SchemaVersion)

	// The version verifies and opens.
	dir, release, err := db.Resolve(ctx, cacheDir, "")
	require.NoError(t, err)
	release()
	assert.Equal(t, filepath.Join(dbDir, "versions", m.Version), dir)

	// Nothing is staged.
	entries, err := os.ReadDir(filepath.Join(dbDir, "staging"))
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestClient_Download_InterruptedKeepsOldVersion verifies that an interrupted
// download does not disturb the active version.
func TestClient_Download_InterruptedKeepsOldVersion(t *testing.T) {
	ctx := clock.With(t.Context(), time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC))
	cacheDir := t.TempDir()
	dbDir := db.Dir(cacheDir)

	// First install a good version.
	good := dbtest.NewFakeDB(t, "testdata/db.tar.gz", dbtest.FakeDBOptions{})
	require.NoError(t, db.NewClient(dbDir, true, db.WithOCIArtifact(good)).Download(ctx, dbDir, ftypes.RegistryOptions{}))
	before, ok := db.ActiveManifest(cacheDir)
	require.True(t, ok)

	// Then attempt a download whose layer cannot be decompressed.
	img := new(fakei.FakeImage)
	bad := oci.NewArtifact("dummy", ftypes.RegistryOptions{}, oci.WithImage(img))
	client := db.NewClient(dbDir, true, db.WithOCIArtifact(bad))
	err := client.Download(ctx, dbDir, ftypes.RegistryOptions{})
	require.Error(t, err)

	// The old version is still active and verifies.
	after, ok := db.ActiveManifest(cacheDir)
	require.True(t, ok)
	assert.Equal(t, before.Version, after.Version)

	_, release, err := db.Resolve(ctx, cacheDir, "")
	require.NoError(t, err)
	release()
}

func TestResolve_PinnedVersion(t *testing.T) {
	ctx := clock.With(t.Context(), time.Now())
	cacheDir := t.TempDir()

	// Build two versions by hand.
	s, err := db.OpenStore(cacheDir, db.DefaultStoreOptions())
	require.NoError(t, err)

	makeDir := func(name string) string {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy.db"), []byte(name), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"),
			[]byte(`{"Version":2,"NextUpdate":"3000-01-01T00:00:00Z","UpdatedAt":"2026-01-01T00:00:00Z"}`), 0o600))
		return dir
	}

	first, err := s.InstallFromDir(ctx, makeDir("first"), store.InstallOptions{Now: time.Now().Add(-time.Hour)})
	require.NoError(t, err)
	require.NoError(t, s.Activate(ctx, first.Version))

	second, err := s.InstallFromDir(ctx, makeDir("second"), store.InstallOptions{Now: time.Now()})
	require.NoError(t, err)
	require.NoError(t, s.Activate(ctx, second.Version))

	// Active resolves to the second.
	dir, release, err := db.Resolve(ctx, cacheDir, "")
	require.NoError(t, err)
	release()
	assert.Equal(t, filepath.Join(db.StoreDir(cacheDir), "versions", second.Version), dir)

	// Pinning the first must not change the active version.
	dir, release, err = db.Resolve(ctx, cacheDir, first.Version)
	require.NoError(t, err)
	release()
	assert.Equal(t, filepath.Join(db.StoreDir(cacheDir), "versions", first.Version), dir)

	m, ok := db.ActiveManifest(cacheDir)
	require.True(t, ok)
	assert.Equal(t, second.Version, m.Version)
}

func TestResolve_PinnedMissingVersion(t *testing.T) {
	cacheDir := t.TempDir()
	s, err := db.OpenStore(cacheDir, db.DefaultStoreOptions())
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy.db"), []byte("x"), 0o600))
	m, err := s.InstallFromDir(t.Context(), dir, store.InstallOptions{})
	require.NoError(t, err)
	require.NoError(t, s.Activate(t.Context(), m.Version))

	_, _, err = db.Resolve(t.Context(), cacheDir, "does-not-exist")
	require.Error(t, err)
	assert.True(t, db.IsVersionMismatch(err), "expected version mismatch, got %#v", err)

	var se *store.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, store.ExitVersionMismatch, se.ExitCode())
}

func TestResolve_NoDatabase(t *testing.T) {
	cacheDir := t.TempDir()
	_, release, err := db.Resolve(t.Context(), cacheDir, "")
	assert.Nil(t, release)
	require.Error(t, err)
	assert.True(t, db.IsUnavailable(err), "expected unavailable, got %#v", err)
}

func TestResolve_LegacyDatabaseFallback(t *testing.T) {
	cacheDir := t.TempDir()
	dbDir := db.Dir(cacheDir)
	require.NoError(t, os.MkdirAll(dbDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dbDir, "trivy.db"), []byte("legacy"), 0o600))
	require.NoError(t, metadata.NewClient(dbDir).Update(metadata.Metadata{Version: db.SchemaVersion}))

	dir, release, err := db.Resolve(t.Context(), cacheDir, "")
	require.NoError(t, err)
	release()
	assert.Equal(t, dbDir, dir)
}

func TestStoreOptions_RetentionDefault(t *testing.T) {
	opts := db.DefaultStoreOptions()
	assert.Equal(t, 2, opts.Retention)
	require.NoError(t, db.CleanStore(t.Context(), t.TempDir(), opts))
}

// TestNeedsUpdate_LegacyStaysLegacy ensures the versioned store is not adopted
// merely because opening it created an empty versions directory.
func TestNeedsUpdate_LegacyStaysLegacy(t *testing.T) {
	cacheDir := t.TempDir()
	dbDir := db.Dir(cacheDir)
	require.NoError(t, os.MkdirAll(dbDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dbDir, "trivy.db"), []byte("legacy"), 0o600))
	require.NoError(t, metadata.NewClient(dbDir).Update(metadata.Metadata{
		Version:      db.SchemaVersion,
		NextUpdate:   time.Now().Add(24 * time.Hour),
		DownloadedAt: time.Now(),
	}))

	client := db.NewClient(dbDir, true)
	needs, err := client.NeedsUpdate(t.Context(), "dev", true)
	require.NoError(t, err)
	assert.False(t, needs)

	// No version was created by the legacy path.
	_, ok := db.ActiveManifest(cacheDir)
	assert.False(t, ok)
}

func TestNeedsUpdate_CorruptActiveVersion(t *testing.T) {
	cacheDir := t.TempDir()
	dbDir := db.Dir(cacheDir)
	s, err := db.OpenStore(cacheDir, db.DefaultStoreOptions())
	require.NoError(t, err)
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "trivy.db"), []byte("original"), 0o600))
	m, err := s.InstallFromDir(t.Context(), src, store.InstallOptions{})
	require.NoError(t, err)
	require.NoError(t, s.Activate(t.Context(), m.Version))

	// Corrupt the active database.
	require.NoError(t, os.WriteFile(filepath.Join(dbDir, "versions", m.Version, "trivy.db"),
		[]byte("corrupt!"), 0o600))

	client := db.NewClient(dbDir, true)

	// Without --skip-db-update, an update is reported as needed.
	needs, err := client.NeedsUpdate(t.Context(), "dev", false)
	require.NoError(t, err)
	assert.True(t, needs)

	// With --skip-db-update, the unusable database is an error, not a silent
	// success.
	_, err = client.NeedsUpdate(t.Context(), "dev", true)
	require.Error(t, err)
	assert.True(t, db.IsUnavailable(err), "got %#v", err)
}
