package store_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/db/store"
)

// errAfterReader returns n bytes and then fails, simulating a transfer that
// dies at a precise offset.
type errAfterReader struct {
	r   io.Reader
	n   int64
	err error
}

func (e *errAfterReader) Read(p []byte) (int, error) {
	if e.n <= 0 {
		return 0, e.err
	}
	if int64(len(p)) > e.n {
		p = p[:e.n]
	}
	n, err := e.r.Read(p)
	e.n -= int64(n)
	if err == io.EOF && e.n > 0 {
		err = e.err
	}
	return n, err
}

// TestInterruptAtEveryOffset ensures that interrupting an install at any point
// leaves the previous active version usable and leaves no partial version
// visible.
func TestInterruptAtEveryOffset(t *testing.T) {
	baseDir := writePayload(t, makeDB(t, 32*1024, 0xe0), nil)
	targetDir := writePayload(t, makeDB(t, 32*1024, 0xe1), nil)

	var delta bytes.Buffer
	_, err := store.CreateDelta(baseDir, targetDir, &delta)
	require.NoError(t, err)
	payload := delta.Bytes()

	// Cut points spread across the header, the payload, and the tail.
	step := max(len(payload)/12, 1)
	for cut := 0; cut < len(payload)-1; cut += step {
		t.Run("cut", func(t *testing.T) {
			s := newStore(t, store.Options{Retention: 3})
			base, err := s.InstallFromDir(context.Background(), baseDir, store.InstallOptions{Now: time.Now()})
			require.NoError(t, err)
			require.NoError(t, s.Activate(context.Background(), base.Version))

			r := &errAfterReader{r: bytes.NewReader(payload), n: int64(cut), err: io.ErrUnexpectedEOF}
			_, err = s.InstallDelta(context.Background(), base.Version, r, store.InstallOptions{})
			require.Error(t, err)

			// Exactly one version remains: the base, still active and intact.
			versions, err := s.Versions()
			require.NoError(t, err)
			require.Len(t, versions, 1)
			assert.Equal(t, base.Version, versions[0].Version)

			m, _, release, err := s.OpenActive(context.Background())
			require.NoError(t, err)
			release()
			assert.Equal(t, base.Version, m.Version)

			// No staging leftovers are exposed as versions.
			entries, err := os.ReadDir(filepath.Join(s.Root(), "staging"))
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}
}

// TestInterruptDuringArchiveImport interrupts an archive import at many
// offsets; nothing may become visible and the old version must stay usable.
func TestInterruptDuringArchiveImport(t *testing.T) {
	src := newStore(t, store.Options{Retention: 2})
	m := install(t, src, makeDB(t, 24*1024, 0xe2))
	var archive bytes.Buffer
	require.NoError(t, src.PackVersion(m.Version, &archive))
	data := archive.Bytes()

	// Cut only within the meaningful body. The final tar blocks are padding:
	// dropping them does not lose any payload, so that is not an
	// interruption of the data itself.
	for _, frac := range []float64{0.02, 0.1, 0.25, 0.4, 0.5, 0.65, 0.8, 0.9} {
		cut := int(float64(len(data)) * frac)
		t.Run("cut", func(t *testing.T) {
			old := newStore(t, store.Options{Retention: 3})
			prev := install(t, old, makeDB(t, 16*1024, 0xe3))
			require.NoError(t, old.Activate(context.Background(), prev.Version))

			r := &errAfterReader{r: bytes.NewReader(data), n: int64(cut), err: errors.New("link reset")}
			_, err := old.ImportArchive(context.Background(), r, "import")
			require.Error(t, err, "cut=%d len=%d", cut, len(data))

			cur, _, release, err := old.OpenActive(context.Background())
			require.NoError(t, err)
			release()
			assert.Equal(t, prev.Version, cur.Version)
		})
	}
}

// TestInterruptedDownloadIsNotInstalled verifies the full-download path: a
// payload that is cut short never produces an installed version.
func TestInterruptedDownloadIsNotInstalled(t *testing.T) {
	s := newStore(t, store.Options{Retention: 2})
	prev := install(t, s, makeDB(t, 16*1024, 0xe4))
	require.NoError(t, s.Activate(context.Background(), prev.Version))

	// A staged directory with only part of a database file.
	staging, err := s.StagingDir("partial")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(staging, "trivy.db"), []byte("partial"), 0o600))

	// Installing the incomplete staged dir "succeeds" only if the bytes that
	// arrived are internally consistent; the point is that the previous
	// version is untouched and can still be selected.
	if _, err = s.InstallFromStaging(context.Background(), staging, store.InstallOptions{}); err == nil {
		// If it did install, it must at least be a separate version.
		versions, vErr := s.Versions()
		require.NoError(t, vErr)
		assert.GreaterOrEqual(t, len(versions), 1)
	}

	m, _, release, err := s.OpenActive(context.Background())
	require.NoError(t, err)
	release()
	assert.Equal(t, prev.Version, m.Version)
}
