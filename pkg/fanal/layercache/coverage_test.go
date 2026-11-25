package layercache_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/layercache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestStateString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "absent", layercache.StateAbsent.String())
	assert.Equal(t, "inflight", layercache.StateInflight.String())
	assert.Equal(t, "written", layercache.StateWritten.String())
	assert.Equal(t, "stale", layercache.StateStale.String())
	assert.Equal(t, "unknown", layercache.State(99).String())
}

func TestNewWithLogger(t *testing.T) {
	t.Parallel()

	idx := layercache.New(cache.NewMemoryCache(), layercache.WithLogger(safeLogger()))
	assert.NotNil(t, idx)

	// A nil logger must not panic and must keep the default.
	idxNil := layercache.New(cache.NewMemoryCache(), layercache.WithLogger(nil))
	assert.NotNil(t, idxNil)
}

func TestIndexPutNilAnalyze(t *testing.T) {
	t.Parallel()

	idx := layercache.New(cache.NewMemoryCache(), layercache.WithLogger(safeLogger()))
	_, err := idx.Put(t.Context(), "sha256:nil-analyze", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "analyze function is nil")
}

// writeFailingCache fails PutBlob to exercise the index store-error branch.
type writeFailingCache struct {
	cache.Cache
}

func (w *writeFailingCache) PutBlob(context.Context, string, types.BlobInfo) error {
	return errors.New("disk full")
}

func TestIndexPutBlobFailureReleasesInflight(t *testing.T) {
	t.Parallel()

	idx := layercache.New(&writeFailingCache{Cache: cache.NewMemoryCache()}, layercache.WithLogger(safeLogger()))
	key := "sha256:store-fail"

	_, err := idx.Put(t.Context(), key, func(context.Context) (types.BlobInfo, error) {
		return sampleBlob(key), nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store layer")

	_, state, err := idx.Get(t.Context(), key)
	require.NoError(t, err)
	assert.Equal(t, layercache.StateAbsent, state)
}

func TestIndexWaiterReceivesHolderError(t *testing.T) {
	t.Parallel()

	c := cache.NewMemoryCache()
	idx := layercache.New(c, layercache.WithLogger(safeLogger()))
	key := "sha256:holder-fails"
	started := make(chan struct{})
	release := make(chan struct{})
	wantErr := errors.New("layer pull failed")

	// The holder blocks until the waiter has joined, guaranteeing the waiter
	// really parks on the inflight entry instead of racing the registration.
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		_, err := idx.Put(t.Context(), key, func(context.Context) (types.BlobInfo, error) {
			close(started)
			<-release
			return types.BlobInfo{}, wantErr
		})
		assert.ErrorIs(t, err, wantErr)
	}()

	<-started
	require.Eventually(t, func() bool {
		_, state, err := idx.Get(t.Context(), key)
		return err == nil && state == layercache.StateInflight
	}, 2_000_000_000, 5_000_000)

	// The waiter joins while the holder is blocked, then the holder fails and
	// the waiter observes the same error without running analyze itself.
	var waiterAnalyzed atomic.Bool
	waiterEntered := make(chan struct{})
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		// Signal that the waiter goroutine has started before it blocks in Put.
		close(waiterEntered)
		_, err := idx.Put(t.Context(), key, func(context.Context) (types.BlobInfo, error) {
			waiterAnalyzed.Store(true)
			return types.BlobInfo{}, nil
		})
		assert.ErrorIs(t, err, wantErr)
	}()

	<-waiterEntered
	// Block the main goroutine until the waiter is parked: because the holder
	// still holds the inflight entry, the waiter's Put can only return once the
	// holder fails. A short Eventually loop gives the scheduler time to park it.
	require.Eventually(t, func() bool {
		// The waiter cannot complete before release is closed, so an uncompleted
		// waiterDone here means it is parked; retry briefly to let it schedule.
		select {
		case <-waiterDone:
			return false
		default:
			return true
		}
	}, 2_000_000_000, 1_000_000)

	close(release)
	<-holderDone
	<-waiterDone
	assert.False(t, waiterAnalyzed.Load(), "the waiter must never run analyze")

	_, state, err := idx.Get(t.Context(), key)
	require.NoError(t, err)
	assert.Equal(t, layercache.StateAbsent, state)
}

func TestIndexResetClearsInflight(t *testing.T) {
	t.Parallel()

	idx := newIndex(cache.NewMemoryCache())
	key := "sha256:reset-nonempty"
	started := make(chan struct{})
	holderCtx, cancel := context.WithCancel(t.Context())

	go func() {
		_, _ = idx.Put(holderCtx, key, func(ctx context.Context) (types.BlobInfo, error) {
			close(started)
			<-ctx.Done()
			return types.BlobInfo{}, ctx.Err()
		})
	}()

	<-started

	// The table is non-empty while the analysis is registered.
	require.Eventually(t, func() bool {
		_, state, err := idx.Get(t.Context(), key)
		return err == nil && state == layercache.StateInflight
	}, 2_000_000_000, 5_000_000)

	// Reset closes and removes every pending entry.
	idx.Reset()
	// The holder then fails its analysis, so nothing is written to the cache
	// and the key resolves as absent.
	cancel()

	require.Eventually(t, func() bool {
		_, state, err := idx.Get(t.Context(), key)
		return err == nil && state == layercache.StateAbsent
	}, 2_000_000_000, 5_000_000)
}

func TestIndexArtifactStateBranches(t *testing.T) {
	t.Parallel()

	t.Run("stale schema version", func(t *testing.T) {
		t.Parallel()
		c := cache.NewMemoryCache()
		ctx := t.Context()
		require.NoError(t, c.PutArtifact(ctx, "sha256:img", types.ArtifactInfo{SchemaVersion: 99}))

		idx := newIndex(c)
		info, state, err := idx.ArtifactState(ctx, "sha256:img")
		require.NoError(t, err)
		assert.Equal(t, layercache.StateStale, state)
		assert.Equal(t, 99, info.SchemaVersion)
	})

	t.Run("corrupted JSON treated as absent", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		fs, err := cache.NewFSCache(dir)
		require.NoError(t, err)
		require.NoError(t, fs.Close())

		db, err := bolt.Open(filepath.Join(dir, "fanal", "fanal.db"), 0o600,
			&bolt.Options{Timeout: 5_000_000_000})
		require.NoError(t, err)
		require.NoError(t, db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("artifact")).Put([]byte("sha256:broken"), []byte("{bad"))
		}))
		require.NoError(t, db.Close())

		fs, err = cache.NewFSCache(dir)
		require.NoError(t, err)
		t.Cleanup(func() { _ = fs.Close() })

		idx := newIndex(fs)
		_, state, err := idx.ArtifactState(t.Context(), "sha256:broken")
		require.NoError(t, err)
		assert.Equal(t, layercache.StateAbsent, state)
	})
}

func TestIndexCommitArtifactError(t *testing.T) {
	t.Parallel()

	idx := layercache.New(&commitFailingCache{Cache: cache.NewMemoryCache()}, layercache.WithLogger(safeLogger()))
	err := idx.(interface {
		CommitArtifact(context.Context, string, types.ArtifactInfo) error
	}).CommitArtifact(t.Context(), "sha256:img", types.ArtifactInfo{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commit artifact")
}

type commitFailingCache struct {
	cache.Cache
}

func (c *commitFailingCache) PutArtifact(context.Context, string, types.ArtifactInfo) error {
	return errors.New("artifact store error")
}

func TestLayerKeyEmptyInputs(t *testing.T) {
	t.Parallel()

	key, err := layercache.LayerKey("", "")
	require.NoError(t, err)
	assert.Len(t, key, len("sha256:")+64)

	// Different artifact types never collide even on an empty base key.
	other, err := layercache.LayerKey("", types.TypeFilesystem)
	require.NoError(t, err)
	assert.NotEqual(t, key, other)
}
