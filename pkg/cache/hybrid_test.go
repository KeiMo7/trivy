package cache_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// safeLogger returns a goroutine-safe logger; the package-level deferred
// default handler is not safe for concurrent use.
func safeLogger() *log.Logger {
	return log.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// failingRemote is an ArtifactCache whose write/delete operations fail, so the
// hybrid downgrade behavior can be exercised without a live Redis server.
type failingRemote struct {
	missingArtifact bool
	missingBlobs    []string
}

func (f *failingRemote) MissingBlobs(context.Context, string, []string) (bool, []string, error) {
	return f.missingArtifact, f.missingBlobs, nil
}

func (f *failingRemote) PutArtifact(context.Context, string, types.ArtifactInfo) error {
	return errors.New("remote artifact write failed")
}

func (f *failingRemote) PutBlob(context.Context, string, types.BlobInfo) error {
	return errors.New("remote blob write failed")
}

func (f *failingRemote) DeleteBlobs(context.Context, []string) error {
	return errors.New("remote delete failed")
}

func TestHybridCache_RemoteWriteFailureKeepsLocalResult(t *testing.T) {
	t.Parallel()

	backends := map[string]cache.LocalArtifactCache{
		"memory": cache.NewMemoryCache(),
		"fs":     mustFSCache(t),
	}

	for name, local := range backends {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hc := cache.NewHybridCache(local, &failingRemote{}, cache.WithHybridLogger(safeLogger()))
			ctx := t.Context()

			// Writes fail remotely but must not return an error and must keep
			// the locally computed result.
			require.NoError(t, hc.PutBlob(ctx, "sha256:blob", types.BlobInfo{
				SchemaVersion: types.BlobJSONSchemaVersion,
				DiffID:        "sha256:blob",
			}))
			require.NoError(t, hc.PutArtifact(ctx, "sha256:artifact", types.ArtifactInfo{
				SchemaVersion: types.ArtifactJSONSchemaVersion,
			}))

			// Reads are served exclusively by the local backend.
			blob, err := hc.GetBlob(ctx, "sha256:blob")
			require.NoError(t, err)
			assert.Equal(t, "sha256:blob", blob.DiffID)

			artifact, err := hc.GetArtifact(ctx, "sha256:artifact")
			require.NoError(t, err)
			assert.Equal(t, types.ArtifactJSONSchemaVersion, artifact.SchemaVersion)
		})
	}
}

func TestHybridCache_MissingBlobsDelegatesToRemote(t *testing.T) {
	t.Parallel()

	remote := &failingRemote{
		missingArtifact: true,
		missingBlobs:    []string{"sha256:m1", "sha256:m2"},
	}
	hc := cache.NewHybridCache(cache.NewMemoryCache(), remote, cache.WithHybridLogger(safeLogger()))

	missingArtifact, missingBlobs, err := hc.MissingBlobs(t.Context(), "sha256:image",
		[]string{"sha256:m1", "sha256:m2"})
	require.NoError(t, err)
	assert.True(t, missingArtifact)
	assert.Equal(t, []string{"sha256:m1", "sha256:m2"}, missingBlobs)
}

func TestHybridCache_DeleteBlobsAggregatesPartialFailure(t *testing.T) {
	t.Parallel()

	local := cache.NewMemoryCache()
	require.NoError(t, local.PutBlob(t.Context(), "sha256:blob", types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
	}))

	hc := cache.NewHybridCache(local, &failingRemote{}, cache.WithHybridLogger(safeLogger()))
	err := hc.DeleteBlobs(t.Context(), []string{"sha256:blob"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote DeleteBlobs")

	// The local deletion still happened.
	_, err = local.GetBlob(t.Context(), "sha256:blob")
	require.Error(t, err)
}

func TestHybridCache_ImplementsCache(t *testing.T) {
	t.Parallel()

	var _ cache.Cache = cache.NewHybridCache(cache.NewMemoryCache(), &failingRemote{}, cache.WithHybridLogger(safeLogger()))
}

func mustFSCache(t *testing.T) cache.LocalArtifactCache {
	t.Helper()
	fs, err := cache.NewFSCache(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}
