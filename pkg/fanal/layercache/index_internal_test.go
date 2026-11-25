package layercache

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func testLogger() *log.Logger {
	return log.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestIndexInflightCount(t *testing.T) {
	t.Parallel()

	idx := New(cache.NewMemoryCache(), WithLogger(testLogger())).(*index)
	ctx := t.Context()

	key := "sha256:inflight-count"
	started := make(chan struct{})
	release := make(chan struct{})

	go func() {
		_, _ = idx.Put(ctx, key, func(context.Context) (types.BlobInfo, error) {
			close(started)
			<-release
			return types.BlobInfo{SchemaVersion: types.BlobJSONSchemaVersion}, nil
		})
	}()

	<-started
	assert.Equal(t, 1, idx.inflightCount(), "the table holds the single in-progress analysis")

	close(release)
	require.Eventually(t, func() bool {
		// A committed entry stays registered for this scan, so the table
		// remains bounded by the distinct layer count.
		return idx.inflightCount() == 1
	}, 2_000_000_000, 5_000_000)

	idx.Reset()
	assert.Equal(t, 0, idx.inflightCount(), "Reset empties the inflight table")
}

func TestNewDefaultConstructor(t *testing.T) {
	t.Parallel()

	idx := New(cache.NewMemoryCache())
	assert.NotNil(t, idx)
	assert.IsType(t, &index{}, idx)
}
