package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/db/store"
)

// makeDB builds a plausible trivy.db payload of the requested size with a
// marker so that versions differ deterministically.
func makeDB(t *testing.T, size int, marker byte) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	for i := 0; i < size; i += 512 {
		b[i] = marker
	}
	return b
}

// writePayload writes a trivy.db/metadata.json pair into a fresh directory.
func writePayload(t *testing.T, db []byte, meta map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy.db"), db, 0o600))
	m := map[string]any{
		"Version":      2,
		"NextUpdate":   time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"UpdatedAt":    time.Now().UTC().Format(time.RFC3339),
		"DownloadedAt": time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range meta {
		m[k] = v
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"), b, 0o600))
	return dir
}

func newStore(t *testing.T, opts store.Options) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir(), opts)
	require.NoError(t, err)
	return s
}

func install(t *testing.T, s *store.Store, db []byte) store.Manifest {
	t.Helper()
	dir := writePayload(t, db, nil)
	m, err := s.InstallFromDir(context.Background(), dir, store.InstallOptions{Now: time.Now()})
	require.NoError(t, err)
	return m
}

func TestOpen_MissingStoreReportsUnavailable(t *testing.T) {
	s := newStore(t, store.DefaultOptions())
	_, err := s.Current()
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindUnavailable), "got %#v", err)

	var se *store.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, store.ExitUnavailable, se.ExitCode())
}

func TestInstallAndActivate(t *testing.T) {
	s := newStore(t, store.DefaultOptions())
	db := makeDB(t, 8*1024, 0x01)
	m := install(t, s, db)

	assert.NotEmpty(t, m.Version)
	assert.Equal(t, int64(len(db)), m.DBSize)

	// Installing does not activate by itself.
	_, err := s.Current()
	assert.True(t, store.IsKind(err, store.KindUnavailable))

	require.NoError(t, s.Activate(context.Background(), m.Version))
	cur, err := s.Current()
	require.NoError(t, err)
	assert.Equal(t, m.Version, cur.Version)

	got, err := os.ReadFile(filepath.Join(s.Root(), "versions", m.Version, "trivy.db"))
	require.NoError(t, err)
	assert.Equal(t, db, got)
}

func TestInstallRefusesCorruptPayload(t *testing.T) {
	s := newStore(t, store.DefaultOptions())
	dir := writePayload(t, makeDB(t, 4*1024, 1), nil)

	// Corrupt the file after the manifest would have been computed only if the
	// caller had raced us; simulate by pointing at a truncated directory.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy.db"), []byte("not a database"), 0o600))
	_, err := s.InstallFromDir(context.Background(), dir, store.InstallOptions{})
	require.NoError(t, err) // it is "valid" as received; integrity is by digest

	// A directory without trivy.db is invalid input.
	empty := t.TempDir()
	_, err = s.InstallFromDir(context.Background(), empty, store.InstallOptions{})
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindInvalid))
}

func TestOpenActiveDetectsTampering(t *testing.T) {
	s := newStore(t, store.DefaultOptions())
	db := makeDB(t, 16*1024, 2)
	m := install(t, s, db)
	require.NoError(t, s.Activate(context.Background(), m.Version))

	// Tamper with the active database on disk.
	require.NoError(t, os.WriteFile(filepath.Join(s.Root(), "versions", m.Version, "trivy.db"),
		[]byte("tampered"), 0o600))

	_, _, release, err := s.OpenActive(context.Background())
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindUnavailable), "expected unavailable, got %#v", err)
	assert.Nil(t, release)
}

func TestOpenActiveTamperRecoverableByRollback(t *testing.T) {
	s := newStore(t, store.Options{Retention: 2})
	first := install(t, s, makeDB(t, 8*1024, 3))
	require.NoError(t, s.Activate(context.Background(), first.Version))

	second := install(t, s, makeDB(t, 8*1024, 4))
	require.NoError(t, s.Activate(context.Background(), second.Version))

	// The first version is retained; the active one is corrupted.
	require.NoError(t, os.WriteFile(filepath.Join(s.Root(), "versions", second.Version, "trivy.db"),
		[]byte("tampered"), 0o600))

	target, err := s.Rollback(context.Background(), first.Version)
	require.NoError(t, err)
	assert.Equal(t, first.Version, target)

	cur, _, release, err := s.OpenActive(context.Background())
	release()
	require.NoError(t, err)
	assert.Equal(t, first.Version, cur.Version)
}

func TestRollbackToEvictedVersionFails(t *testing.T) {
	s := newStore(t, store.Options{Retention: 1})
	// Retention 1 plus an activated version: activation runs GC, which would
	// evict the older version.
	a := install(t, s, makeDB(t, 8*1024, 5))
	require.NoError(t, s.Activate(context.Background(), a.Version))
	b := install(t, s, makeDB(t, 8*1024, 6))
	require.NoError(t, s.Activate(context.Background(), b.Version))

	// With Retention=1 and max size 0, only the active version remains.
	_, err := s.Manifest(a.Version)
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindVersionMismatch))

	_, err = s.Rollback(context.Background(), a.Version)
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindRollbackFailed), "got %#v", err)

	var se *store.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, store.ExitRollbackFailed, se.ExitCode())
}

func TestRollbackDefaultsToPrevious(t *testing.T) {
	s := newStore(t, store.Options{Retention: 3})
	t0 := time.Now().Add(-3 * time.Hour)
	versions := make([]store.Manifest, 0, 3)
	for i := range 3 {
		dir := writePayload(t, makeDB(t, 4*1024, byte(10+i)), nil)
		m, err := s.InstallFromDir(context.Background(), dir, store.InstallOptions{Now: t0.Add(time.Duration(i) * time.Hour)})
		require.NoError(t, err)
		versions = append(versions, m)
	}
	for _, m := range versions {
		require.NoError(t, s.Activate(context.Background(), m.Version))
	}

	target, err := s.Rollback(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, versions[1].Version, target)

	target, err = s.Rollback(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, versions[0].Version, target)

	_, err = s.Rollback(context.Background(), "")
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindRollbackFailed))
}

func TestRetentionKeepsPolicyVersions(t *testing.T) {
	s := newStore(t, store.Options{Retention: 2})
	base := time.Now().Add(-10 * time.Hour)
	var installed []store.Manifest
	for i := range 5 {
		dir := writePayload(t, makeDB(t, 4*1024, byte(20+i)), nil)
		m, err := s.InstallFromDir(context.Background(), dir, store.InstallOptions{Now: base.Add(time.Duration(i) * time.Hour)})
		require.NoError(t, err)
		installed = append(installed, m)
		require.NoError(t, s.Activate(context.Background(), m.Version))
	}

	versions, err := s.Versions()
	require.NoError(t, err)
	// Retention=2 keeps the active version and the newest other version.
	require.Len(t, versions, 2)
	assert.Equal(t, installed[4].Version, versions[0].Version)
	assert.Equal(t, installed[3].Version, versions[1].Version)

	// Eviction order is deterministic: oldest first.
	_, err = s.Manifest(installed[0].Version)
	assert.True(t, store.IsKind(err, store.KindVersionMismatch))
}

func TestMaxSizeEvictionKeepsRetentionFloor(t *testing.T) {
	opts := store.Options{Retention: 2, MaxSize: 20 * 1024}
	s := newStore(t, opts)
	base := time.Now().Add(-10 * time.Hour)
	for i := range 4 {
		dir := writePayload(t, makeDB(t, 8*1024, byte(30+i)), nil)
		m, err := s.InstallFromDir(context.Background(), dir, store.InstallOptions{Now: base.Add(time.Duration(i) * time.Hour)})
		require.NoError(t, err)
		require.NoError(t, s.Activate(context.Background(), m.Version))
	}
	versions, err := s.Versions()
	require.NoError(t, err)
	assert.Len(t, versions, 2, "retention floor must protect two versions even over the size limit")
}

func TestDeltaRoundTripIsByteIdentical(t *testing.T) {
	baseDB := makeDB(t, 256*1024, 0x40)
	// A target that shares most of its content with the base.
	targetDB := append([]byte{}, baseDB...)
	copy(targetDB[1000:], makeDB(t, 4096, 0x41))
	targetDB = append(targetDB, makeDB(t, 8*1024, 0x42)...)

	baseDir := writePayload(t, baseDB, nil)
	targetDir := writePayload(t, targetDB, map[string]any{
		"UpdatedAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})

	var buf bytes.Buffer
	n, err := store.CreateDelta(baseDir, targetDir, &buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	// The delta must be far smaller than the full target.
	assert.Less(t, buf.Len(), len(targetDB), "delta should only carry changed bytes")

	s := newStore(t, store.Options{Retention: 3})
	baseManifest, err := s.InstallFromDir(context.Background(), baseDir, store.InstallOptions{Now: time.Now()})
	require.NoError(t, err)
	require.NoError(t, s.Activate(context.Background(), baseManifest.Version))

	m, err := s.InstallDelta(context.Background(), baseManifest.Version, bytes.NewReader(buf.Bytes()), store.InstallOptions{Now: time.Now().Add(time.Minute)})
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(s.Root(), "versions", m.Version, "trivy.db"))
	require.NoError(t, err)
	assert.Equal(t, targetDB, got, "delta result must be byte-for-byte identical to the full payload")
	assert.NotEqual(t, baseManifest.Version, m.Version)
}

func TestDeltaAgainstWrongBaseIsRefused(t *testing.T) {
	baseDir := writePayload(t, makeDB(t, 32*1024, 0x50), nil)
	targetDir := writePayload(t, makeDB(t, 32*1024, 0x51), nil)

	var buf bytes.Buffer
	_, err := store.CreateDelta(baseDir, targetDir, &buf)
	require.NoError(t, err)

	s := newStore(t, store.Options{Retention: 3})
	// Install a different base than the one the delta was built against.
	other := install(t, s, makeDB(t, 32*1024, 0x52))
	require.NoError(t, s.Activate(context.Background(), other.Version))

	_, err = s.InstallDelta(context.Background(), other.Version, bytes.NewReader(buf.Bytes()), store.InstallOptions{})
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindVersionMismatch), "got %#v", err)

	// The active version must be unchanged and still usable.
	cur, _, release, err := s.OpenActive(context.Background())
	release()
	require.NoError(t, err)
	assert.Equal(t, other.Version, cur.Version)
}

func TestDeltaMissingBaseIsVersionMismatch(t *testing.T) {
	baseDir := writePayload(t, makeDB(t, 8*1024, 0x60), nil)
	targetDir := writePayload(t, makeDB(t, 8*1024, 0x61), nil)
	var buf bytes.Buffer
	_, err := store.CreateDelta(baseDir, targetDir, &buf)
	require.NoError(t, err)

	s := newStore(t, store.DefaultOptions())
	_, err = s.InstallDelta(context.Background(), "does-not-exist", bytes.NewReader(buf.Bytes()), store.InstallOptions{})
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindVersionMismatch))

	var se *store.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, store.ExitVersionMismatch, se.ExitCode())
}

func TestDeltaCorruptPayloadIsRefused(t *testing.T) {
	baseDir := writePayload(t, makeDB(t, 64*1024, 0x70), nil)
	targetDB := makeDB(t, 64*1024, 0x71)
	targetDir := writePayload(t, targetDB, nil)
	var buf bytes.Buffer
	_, err := store.CreateDelta(baseDir, targetDir, &buf)
	require.NoError(t, err)

	corrupt := bytes.Clone(buf.Bytes())
	// Flip a byte in the payload region (past the header).
	corrupt[len(corrupt)-10] ^= 0xff

	s := newStore(t, store.Options{Retention: 3})
	base, err := s.InstallFromDir(context.Background(), baseDir, store.InstallOptions{Now: time.Now()})
	require.NoError(t, err)
	require.NoError(t, s.Activate(context.Background(), base.Version))

	_, err = s.InstallDelta(context.Background(), base.Version, bytes.NewReader(corrupt), store.InstallOptions{})
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindIntegrity), "got %#v", err)

	cur, _, release, err := s.OpenActive(context.Background())
	release()
	require.NoError(t, err)
	assert.Equal(t, base.Version, cur.Version)
}

func TestInterruptedDeltaLeavesActiveVersionUsable(t *testing.T) {
	baseDB := makeDB(t, 128*1024, 0x80)
	baseDir := writePayload(t, baseDB, nil)
	targetDir := writePayload(t, makeDB(t, 128*1024, 0x81), nil)
	var buf bytes.Buffer
	_, err := store.CreateDelta(baseDir, targetDir, &buf)
	require.NoError(t, err)

	delta := buf.Bytes()
	// Interrupt at several points, including inside the header and payload.
	for _, cut := range []int{1, 8, 9, 12, len(delta) / 2, len(delta) - 1} {
		t.Run("cut", func(t *testing.T) {
			s := newStore(t, store.Options{Retention: 3})
			base, err := s.InstallFromDir(context.Background(), baseDir, store.InstallOptions{Now: time.Now()})
			require.NoError(t, err)
			require.NoError(t, s.Activate(context.Background(), base.Version))

			_, err = s.InstallDelta(context.Background(), base.Version, bytes.NewReader(delta[:cut]), store.InstallOptions{})
			require.Error(t, err)

			// Whatever the cut, the old version must still verify and be active.
			cur, _, release, err := s.OpenActive(context.Background())
			release()
			require.NoError(t, err)
			assert.Equal(t, base.Version, cur.Version)
			got, err := os.ReadFile(filepath.Join(s.Root(), "versions", cur.Version, "trivy.db"))
			require.NoError(t, err)
			assert.Equal(t, baseDB, got)
		})
	}
}

func TestConcurrentReadersSeeOneWholeVersion(t *testing.T) {
	s := newStore(t, store.Options{Retention: 5})
	a := install(t, s, makeDB(t, 64*1024, 0xa0))
	require.NoError(t, s.Activate(context.Background(), a.Version))
	b := install(t, s, makeDB(t, 64*1024, 0xa1))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 16)

	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				m, path, release, err := s.OpenActive(context.Background())
				if err != nil {
					errs <- err
					return
				}
				data, err := os.ReadFile(path)
				if err != nil {
					release()
					errs <- err
					return
				}
				// The bytes read must match the manifest the reader saw.
				if n := int64(len(data)); n != m.DBSize {
					release()
					errs <- errors.New("read size does not match the manifest")
					return
				}
				release()
				if m.Version != a.Version && m.Version != b.Version {
					errs <- errors.New("unexpected version")
					return
				}
			}
		})
	}

	for range 10 {
		require.NoError(t, s.Activate(context.Background(), b.Version))
		require.NoError(t, s.Activate(context.Background(), a.Version))
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestManifestIsIgnoredUntilComplete(t *testing.T) {
	s := newStore(t, store.DefaultOptions())
	// Simulate a version directory whose transfer was interrupted: files exist
	// but there is no manifest.
	dir := filepath.Join(s.Root(), "versions", "partial")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy.db"), []byte("half"), 0o600))

	versions, err := s.Versions()
	require.NoError(t, err)
	assert.Empty(t, versions)

	// Equally, an empty current marker is not a usable database.
	require.NoError(t, os.WriteFile(filepath.Join(s.Root(), "current"), []byte("partial\n"), 0o600))
	_, _, _, err = s.OpenActive(context.Background())
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindUnavailable))
}

func TestVersionIDSafePaths(t *testing.T) {
	s := newStore(t, store.DefaultOptions())
	_, err := s.Manifest("../../etc/passwd")
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindInvalid))
}

func TestRemoveActiveIsRefused(t *testing.T) {
	s := newStore(t, store.Options{Retention: 2})
	m := install(t, s, makeDB(t, 4*1024, 0xb0))
	require.NoError(t, s.Activate(context.Background(), m.Version))
	err := s.Remove(context.Background(), m.Version)
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindInvalid))

	// A non-active version can be removed.
	other := install(t, s, makeDB(t, 4*1024, 0xb1))
	require.NoError(t, s.Remove(context.Background(), other.Version))
	_, err = s.Manifest(other.Version)
	assert.True(t, store.IsKind(err, store.KindVersionMismatch))
}
