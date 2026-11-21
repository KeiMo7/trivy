package store_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/db/store"
)

func TestArchiveRoundTrip(t *testing.T) {
	s := newStore(t, store.Options{Retention: 2})
	db := makeDB(t, 96*1024, 0xc0)
	m := install(t, s, db)
	require.NoError(t, s.Activate(context.Background(), m.Version))

	var buf bytes.Buffer
	require.NoError(t, s.PackVersion(m.Version, &buf))

	// Import into a brand-new store on another "machine".
	other := newStore(t, store.Options{Retention: 2})
	got, err := other.ImportArchive(context.Background(), bytes.NewReader(buf.Bytes()), "import")
	require.NoError(t, err)
	assert.Equal(t, m.Version, got.Version)
	assert.Equal(t, m.DBDigest, got.DBDigest)

	require.NoError(t, other.Activate(context.Background(), got.Version))
	data, err := os.ReadFile(filepath.Join(other.Root(), "versions", got.Version, "trivy.db"))
	require.NoError(t, err)
	assert.Equal(t, db, data)
}

func TestArchiveTruncationIsRefused(t *testing.T) {
	s := newStore(t, store.Options{Retention: 2})
	m := install(t, s, makeDB(t, 64*1024, 0xc1))
	var buf bytes.Buffer
	require.NoError(t, s.PackVersion(m.Version, &buf))

	full := buf.Bytes()
	for _, cut := range []int{1, 10, len(full) / 4, len(full) / 2, len(full) - 20} {
		t.Run("truncated", func(t *testing.T) {
			other := newStore(t, store.Options{Retention: 2})
			_, err := other.ImportArchive(context.Background(), bytes.NewReader(full[:cut]), "")
			require.Error(t, err)
			versions, err := other.Versions()
			require.NoError(t, err)
			assert.Empty(t, versions, "a truncated archive must not install anything")
		})
	}
}

func TestArchiveTamperingIsRefused(t *testing.T) {
	s := newStore(t, store.Options{Retention: 2})
	m := install(t, s, makeDB(t, 64*1024, 0xc2))
	var buf bytes.Buffer
	require.NoError(t, s.PackVersion(m.Version, &buf))

	// Flip a byte in the tar payload. gzip wraps it, so decompress, tamper,
	// recompress to keep the container valid.
	tampered := tamperGzip(t, buf.Bytes())
	other := newStore(t, store.Options{Retention: 2})
	_, err := other.ImportArchive(context.Background(), bytes.NewReader(tampered), "")
	require.Error(t, err)
	assert.True(t, store.IsKind(err, store.KindIntegrity), "got %#v", err)
}

func TestDeltaIsDeterministic(t *testing.T) {
	baseDir := writePayload(t, makeDB(t, 64*1024, 0xd0), nil)
	targetDir := writePayload(t, makeDB(t, 64*1024, 0xd1), nil)

	var one, two bytes.Buffer
	_, err := store.CreateDelta(baseDir, targetDir, &one)
	require.NoError(t, err)
	_, err = store.CreateDelta(baseDir, targetDir, &two)
	require.NoError(t, err)
	assert.Equal(t, one.Bytes(), two.Bytes(), "delta creation must be reproducible")
}

func TestDeltaReconstructsMetadataToo(t *testing.T) {
	baseDir := writePayload(t, makeDB(t, 8*1024, 0xd2), map[string]any{"Version": 2})
	// Same database bytes but different metadata: the delta must still carry
	// metadata changes.
	targetDir := writePayload(t, makeDB(t, 8*1024, 0xd3), map[string]any{"Version": 2, "NextUpdate": "2999-01-01T00:00:00Z"})

	var buf bytes.Buffer
	_, err := store.CreateDelta(baseDir, targetDir, &buf)
	require.NoError(t, err)

	s := newStore(t, store.Options{Retention: 3})
	base, err := s.InstallFromDir(context.Background(), baseDir, store.InstallOptions{})
	require.NoError(t, err)
	require.NoError(t, s.Activate(context.Background(), base.Version))
	m, err := s.InstallDelta(context.Background(), base.Version, bytes.NewReader(buf.Bytes()), store.InstallOptions{})
	require.NoError(t, err)

	want, err := os.ReadFile(filepath.Join(targetDir, "metadata.json"))
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(s.Root(), "versions", m.Version, "metadata.json"))
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// tamperGzip decompresses the archive, flips a byte inside the trivy.db entry
// data (past the tar headers), and recompresses it. The container stays valid,
// so the only thing that can catch the change is the payload digest.
func tamperGzip(t *testing.T, in []byte) []byte {
	t.Helper()
	r, err := gzipReader(in)
	require.NoError(t, err)
	var plain bytes.Buffer
	_, err = plain.ReadFrom(r)
	require.NoError(t, err)
	b := plain.Bytes()

	// Locate the "trivy.db" entry header and flip a byte in its data block.
	i := bytes.Index(b, []byte("trivy.db"))
	require.Greater(t, i, -1)
	off := i + 512 + 4096 // header block + some way into the file data
	require.Less(t, off, len(b))
	b[off] ^= 0xff
	return gzipBytes(t, b)
}

func gzipReader(in []byte) (*gzip.Reader, error) {
	return gzip.NewReader(bytes.NewReader(in))
}

func gzipBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(in)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}
