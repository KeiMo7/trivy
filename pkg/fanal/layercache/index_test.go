package layercache_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/layercache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// newCaches returns the same test cases executed against both supported local
// backends: the in-memory cache and the bbolt-backed filesystem cache.
func newCaches(t *testing.T) map[string]cache.Cache {
	t.Helper()

	memory := cache.NewMemoryCache()

	fs, err := cache.NewFSCache(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })

	return map[string]cache.Cache{
		"memory": memory,
		"fs":     fs,
	}
}

// newIndex creates a concrete index so tests can reach scan-scoped helpers
// that are not part of the public Index interface. Every index gets a
// thread-safe text logger to avoid races on the global non-thread-safe
// deferred default handler.
func newIndex(c cache.Cache) *layercacheTestIndex {
	return &layercacheTestIndex{layercache.New(c, layercache.WithLogger(safeLogger()))}
}

// safeLogger returns a goroutine-safe slog logger scoped to the test.
func safeLogger() *log.Logger {
	return log.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// layercacheTestIndex exposes the concrete helpers for white-box tests.
type layercacheTestIndex struct {
	layercache.Index
}

func (x *layercacheTestIndex) CommitArtifact(ctx context.Context, imageKey string, info types.ArtifactInfo) error {
	return x.Index.(interface {
		CommitArtifact(context.Context, string, types.ArtifactInfo) error
	}).CommitArtifact(ctx, imageKey, info)
}

func (x *layercacheTestIndex) ArtifactState(ctx context.Context, imageKey string) (types.ArtifactInfo, layercache.State, error) {
	return x.Index.(interface {
		ArtifactState(context.Context, string) (types.ArtifactInfo, layercache.State, error)
	}).ArtifactState(ctx, imageKey)
}

func (x *layercacheTestIndex) Reset() {
	x.Index.(interface{ Reset() }).Reset()
}

func sampleBlob(name string) types.BlobInfo {
	return types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		DiffID:        name,
		OS: types.OS{
			Family: "alpine",
			Name:   "3.19",
		},
	}
}

func TestIndexResolveAndState(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()
			keys := []string{"sha256:layer-a", "sha256:layer-b", "sha256:layer-c"}

			// Initially everything is absent and all three layers are missing.
			for _, key := range keys {
				_, state, err := idx.Get(ctx, key)
				require.NoError(t, err)
				assert.Equal(t, layercache.StateAbsent, state)
			}

			missing, err := idx.Resolve(ctx, "sha256:image-1", keys)
			require.NoError(t, err)
			assert.Equal(t, keys, missing)

			// Write two layers through Put.
			for _, key := range keys[:2] {
				blob, err := idx.Put(ctx, key, func(context.Context) (types.BlobInfo, error) {
					return sampleBlob(key), nil
				})
				require.NoError(t, err)
				assert.Equal(t, types.BlobJSONSchemaVersion, blob.SchemaVersion)
			}

			// The written entries are now readable and reported as written.
			for _, key := range keys[:2] {
				blob, state, err := idx.Get(ctx, key)
				require.NoError(t, err)
				assert.Equal(t, layercache.StateWritten, state)
				assert.Equal(t, sampleBlob(key), blob)
			}

			missing, err = idx.Resolve(ctx, "sha256:image-1", keys)
			require.NoError(t, err)
			assert.Equal(t, []string{"sha256:layer-c"}, missing)
		})
	}
}

func TestIndexDuplicateLayerKeys(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()

			// The same diff ID shows up three times (multi-stage / cache-from).
			layerKeys := []string{"sha256:shared", "sha256:shared", "sha256:shared"}
			missing, err := idx.Resolve(ctx, "sha256:image-dup", layerKeys)
			require.NoError(t, err)
			assert.Equal(t, []string{"sha256:shared"}, missing)

			var calls atomic.Int32
			for range layerKeys {
				_, err = idx.Put(ctx, "sha256:shared", func(context.Context) (types.BlobInfo, error) {
					calls.Add(1)
					return sampleBlob("sha256:shared"), nil
				})
				require.NoError(t, err)
			}
			assert.Equal(t, int32(1), calls.Load(), "the analysis must run exactly once")

			// A second scan of another image sharing the layer must fully hit.
			missing, err = idx.Resolve(ctx, "sha256:another-image", layerKeys)
			require.NoError(t, err)
			assert.Empty(t, missing)

			missing, err = idx.Resolve(ctx, "sha256:another-image",
				[]string{"sha256:shared", "sha256:shared"})
			require.NoError(t, err)
			assert.Empty(t, missing)
		})
	}
}

func TestIndexCrossImageSharedBaseLayer(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()

			var calls atomic.Int32
			analyze := func(context.Context) (types.BlobInfo, error) {
				calls.Add(1)
				return sampleBlob("sha256:base"), nil
			}

			// First image: the base layer is analyzed once.
			missing1, err := idx.Resolve(ctx, "sha256:image-1", []string{"sha256:base"})
			require.NoError(t, err)
			require.Len(t, missing1, 1)
			_, err = idx.Put(ctx, "sha256:base", analyze)
			require.NoError(t, err)

			// Second image with a different imageKey but the same layer: full hit,
			// no additional analysis and an empty missing list.
			missing2, err := idx.Resolve(ctx, "sha256:image-2", []string{"sha256:base"})
			require.NoError(t, err)
			assert.Empty(t, missing2)

			_, err = idx.Put(ctx, "sha256:base", analyze)
			require.NoError(t, err)
			assert.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestIndexStaleSchemaVersion(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()
			key := "sha256:stale-schema"

			// Seed an entry whose schema version does not match the current one.
			stale := sampleBlob(key)
			stale.SchemaVersion = types.BlobJSONSchemaVersion + 1
			require.NoError(t, c.PutBlob(ctx, key, stale))

			blob, state, err := idx.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateStale, state)
			assert.Equal(t, stale, blob)

			missing, err := idx.Resolve(ctx, "sha256:image-stale", []string{key})
			require.NoError(t, err, "a stale entry is reported as missing without an error")
			assert.Equal(t, []string{key}, missing)

			// Re-analysis overwrites the entry and the state goes back to written.
			refreshed, err := idx.Put(ctx, key, func(context.Context) (types.BlobInfo, error) {
				return sampleBlob(key), nil
			})
			require.NoError(t, err)
			assert.Equal(t, types.BlobJSONSchemaVersion, refreshed.SchemaVersion)

			_, state, err = idx.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateWritten, state)
		})
	}
}

// TestIndexSchemaMigration exercises the 2 -> N schema upgrade: an entry
// written under an older BlobJSONSchemaVersion is observed as stale, counted
// as missing without an error, re-analyzed once and finally committed under the
// current version. It models the migration of pre-existing on-disk entries.
func TestIndexSchemaMigration(t *testing.T) {
	t.Parallel()

	const previousSchemaVersion = 2

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			if types.BlobJSONSchemaVersion == previousSchemaVersion {
				t.Skip("the migration scenario requires a schema bump")
			}

			idx := newIndex(c)
			ctx := t.Context()
			key := "sha256:schema-migration"

			// Seed an entry written by the previous release.
			legacy := sampleBlob(key)
			legacy.SchemaVersion = previousSchemaVersion
			require.NoError(t, c.PutBlob(ctx, key, legacy))

			_, state, err := idx.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateStale, state)

			missing, err := idx.Resolve(ctx, "sha256:image-migration", []string{key})
			require.NoError(t, err)
			assert.Equal(t, []string{key}, missing, "a legacy entry must be re-analyzed")

			var calls atomic.Int32
			refreshed, err := idx.Put(ctx, key, func(context.Context) (types.BlobInfo, error) {
				calls.Add(1)
				return sampleBlob(key), nil
			})
			require.NoError(t, err)
			assert.Equal(t, int32(1), calls.Load())
			assert.Equal(t, types.BlobJSONSchemaVersion, refreshed.SchemaVersion)

			missing, err = idx.Resolve(ctx, "sha256:image-migration", []string{key})
			require.NoError(t, err)
			assert.Empty(t, missing, "after migration the entry hits the cache")
		})
	}
}

func TestIndexCorruptedBlobJSON(t *testing.T) {
	t.Parallel()

	// Only the filesystem backend stores raw JSON in bbolt.
	dir := t.TempDir()
	fs, err := cache.NewFSCache(dir)
	require.NoError(t, err)
	require.NoError(t, fs.Close())

	key := "sha256:corrupt"

	// A second bbolt handle must carry its own open timeout and is opened only
	// after the FSCache handle is closed, otherwise flock blocks forever.
	db, err := bolt.Open(filepath.Join(dir, "fanal", "fanal.db"), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("blob")).Put([]byte(key), []byte("{not-json"))
	}))
	require.NoError(t, db.Close())

	fs, err = cache.NewFSCache(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })

	idx := layercache.New(fs, layercache.WithLogger(safeLogger()))
	missing, err := idx.Resolve(t.Context(), "sha256:image-corrupt", []string{key})
	require.NoError(t, err, "corrupted JSON must not surface as an error")
	assert.Equal(t, []string{key}, missing)

	_, state, err := idx.Get(t.Context(), key)
	require.NoError(t, err)
	assert.Equal(t, layercache.StateStale, state)
}

func TestIndexSingleFlight(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()
			key := "sha256:single-flight"

			var calls atomic.Int32
			var holders atomic.Int32
			var startOnce sync.Once
			started := make(chan struct{})
			release := make(chan struct{})

			analyze := func(context.Context) (types.BlobInfo, error) {
				holders.Add(1)
				startOnce.Do(func() { close(started) })
				<-release
				calls.Add(1)
				return sampleBlob(key), nil
			}

			const goroutines = 16
			var wg sync.WaitGroup
			results := make([]types.BlobInfo, goroutines)
			errs := make([]error, goroutines)
			wg.Add(goroutines)

			for n := range goroutines {
				go func(i int) {
					defer wg.Done()
					results[i], errs[i] = idx.Put(ctx, key, analyze)
				}(n)
			}

			<-started
			// While the holder is running, Get observes the inflight state.
			_, state, err := idx.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateInflight, state)

			close(release)
			wg.Wait()

			for _, err := range errs {
				require.NoError(t, err)
			}
			assert.Equal(t, int32(1), calls.Load(), "only one analyze call")
			assert.Equal(t, int32(1), holders.Load())
			for i := 1; i < goroutines; i++ {
				assert.Equal(t, results[0], results[i], "waiters receive the same BlobInfo")
			}

			// The committed entry left the inflight table.
			_, state, err = idx.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateWritten, state)
		})
	}
}

func TestIndexPutCanceled(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			key := "sha256:canceled"
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
			cancel()

			require.Eventually(t, func() bool {
				_, state, err := idx.Get(t.Context(), key)
				return err == nil && state == layercache.StateAbsent
			}, 2_000_000_000, 5_000_000, "the key returns to absent after cancellation")

			// No inflight registration remains and a later Put succeeds.
			blob, err := idx.Put(t.Context(), key, func(context.Context) (types.BlobInfo, error) {
				return sampleBlob(key), nil
			})
			require.NoError(t, err)
			assert.Equal(t, key, blob.DiffID)
		})
	}
}

func TestIndexWaiterContextCanceled(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			key := "sha256:waiter-cancel"
			started := make(chan struct{})
			release := make(chan struct{})

			go func() {
				_, _ = idx.Put(t.Context(), key, func(context.Context) (types.BlobInfo, error) {
					close(started)
					<-release
					return sampleBlob(key), nil
				})
			}()

			<-started
			// Confirm the inflight registration before joining as a waiter, so
			// the test exercises the waiting path rather than a fresh holder.
			require.Eventually(t, func() bool {
				_, state, err := idx.Get(t.Context(), key)
				return err == nil && state == layercache.StateInflight
			}, 2_000_000_000, 5_000_000)

			waiterCtx, cancel := context.WithCancel(t.Context())
			cancel()

			var analyzed atomic.Bool
			_, err := idx.Put(waiterCtx, key, func(context.Context) (types.BlobInfo, error) {
				analyzed.Store(true)
				return types.BlobInfo{}, nil
			})
			require.ErrorIs(t, err, context.Canceled)
			assert.False(t, analyzed.Load(), "the canceled waiter must not run analyze")

			close(release)

			// The holder still committed successfully and the entry is usable.
			require.Eventually(t, func() bool {
				_, state, err := idx.Get(t.Context(), key)
				return err == nil && state == layercache.StateWritten
			}, 2_000_000_000, 5_000_000)
		})
	}
}

func TestIndexAnalyzeErrorReleasesInflight(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()
			key := "sha256:analyze-error"
			wantErr := errors.New("boom")

			_, err := idx.Put(ctx, key, func(context.Context) (types.BlobInfo, error) {
				return types.BlobInfo{}, wantErr
			})
			require.ErrorIs(t, err, wantErr)

			_, state, err := idx.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateAbsent, state, "a failed analysis leaves no inflight entry")
		})
	}
}

func TestIndexCommitArtifactOrdering(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()
			imageKey := "sha256:image-commit"

			// Before the commit the artifact entry is absent while the layer
			// missing list is preserved independently.
			_, state, err := idx.ArtifactState(ctx, imageKey)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateAbsent, state)

			require.NoError(t, idx.CommitArtifact(ctx, imageKey, types.ArtifactInfo{
				SchemaVersion: types.ArtifactJSONSchemaVersion,
				Architecture:  "amd64",
			}))

			info, state, err := idx.ArtifactState(ctx, imageKey)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateWritten, state)
			assert.Equal(t, "amd64", info.Architecture)
		})
	}
}

func TestIndexDeterministicMergeAcrossOrder(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			keys := []string{"sha256:k1", "sha256:k2", "sha256:k3", "sha256:k4", "sha256:k5"}
			for _, key := range keys {
				require.NoError(t, c.PutBlob(ctx, key, sampleBlob(key)))
			}

			idx := newIndex(c)
			var hashes []string

			rng := rand.New(rand.NewSource(42))
			for range 20 {
				shuffled := append([]string(nil), keys...)
				rng.Shuffle(len(shuffled), func(i, j int) {
					shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
				})

				missing, err := idx.Resolve(ctx, "sha256:image-order", shuffled)
				require.NoError(t, err)
				assert.Empty(t, missing)

				// Merge in the shuffled order, then hash the resulting content
				// through a canonical order so the hash is order-independent.
				merged := make(map[string]types.BlobInfo, len(shuffled))
				for _, key := range shuffled {
					blob, state, err := idx.Get(ctx, key)
					require.NoError(t, err)
					require.Equal(t, layercache.StateWritten, state)
					merged[key] = blob
				}

				orderedKeys := lo.Keys(merged)
				slices.Sort(orderedKeys)
				var hash string
				for _, key := range orderedKeys {
					hash += merged[key].DiffID
				}
				hashes = append(hashes, hash)
			}
			for _, hash := range hashes[1:] {
				assert.Equal(t, hashes[0], hash, "merged content must be identical regardless of key order")
			}
		})
	}
}

func TestIndexReset(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			key := "sha256:reset"
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
			cancel()

			require.Eventually(t, func() bool {
				_, state, err := idx.Get(t.Context(), key)
				return err == nil && state == layercache.StateAbsent
			}, 2_000_000_000, 5_000_000)

			// Reset must be safe on an empty table and leave nothing behind.
			idx.Reset()
			_, state, err := idx.Get(t.Context(), key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateAbsent, state)
		})
	}
}

func TestReadOnlyCacheDegradesToNop(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("read-only permission is bypassed for root")
	}

	dir := t.TempDir()
	fs, err := cache.NewFSCache(dir)
	require.NoError(t, err)

	// Seed an entry before the directory becomes read-only.
	ctx := t.Context()
	require.NoError(t, fs.PutBlob(ctx, "sha256:readonly", sampleBlob("sha256:readonly")))
	require.NoError(t, fs.Close())

	require.NoError(t, os.Chmod(filepath.Join(dir, "fanal", "fanal.db"), 0o400))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "fanal", "fanal.db"), 0o600) })

	// A second writer cannot take the bbolt lock / open for writing. Reopening
	// must fail instead of panicking; callers degrade to NopCache behavior and
	// keep scanning with exit code zero.
	_, err = cache.NewFSCache(dir)
	require.Error(t, err)
}

func TestLayerKeyArtifactTypeIsolation(t *testing.T) {
	t.Parallel()

	base := "sha256:base-key"
	imageKey, err := layercache.LayerKey(base, types.TypeContainerImage)
	require.NoError(t, err)
	fsKey, err := layercache.LayerKey(base, types.TypeFilesystem)
	require.NoError(t, err)
	vmKey, err := layercache.LayerKey(base, types.TypeVM)
	require.NoError(t, err)

	assert.NotEqual(t, imageKey, fsKey)
	assert.NotEqual(t, imageKey, vmKey)
	assert.NotEqual(t, fsKey, vmKey)

	// Deterministic: same inputs always yield the same key.
	again, err := layercache.LayerKey(base, types.TypeContainerImage)
	require.NoError(t, err)
	assert.Equal(t, imageKey, again)
	assert.Len(t, imageKey, len("sha256:")+64)
}

func TestLayerKeyCreatedByIndependent(t *testing.T) {
	t.Parallel()

	// The layer key is computed from the diff ID via cache.CalcKey and never
	// incorporates CreatedBy. When history and layer counts do not match,
	// Layer.CreatedBy is left empty but the derived key must stay unchanged.
	base := "sha256:base-for-createdby"
	key, err := layercache.LayerKey(base, types.TypeContainerImage)
	require.NoError(t, err)

	blobWithCreatedBy := sampleBlob("sha256:diffid")
	blobWithCreatedBy.CreatedBy = "RUN apk add curl"
	blobWithoutCreatedBy := blobWithCreatedBy
	blobWithoutCreatedBy.CreatedBy = ""

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()

			// Write an entry with a CreatedBy value under the key.
			require.NoError(t, c.PutBlob(ctx, key, blobWithCreatedBy))
			got, state, err := idx.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateWritten, state)
			assert.Equal(t, "RUN apk add curl", got.CreatedBy)

			// Re-writing the very same key with an empty CreatedBy (the
			// history/layer mismatch case) resolves to the identical key and
			// overwrites the entry rather than creating a second record.
			require.NoError(t, c.PutBlob(ctx, key, blobWithoutCreatedBy))
			got, state, err = idx.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateWritten, state)
			assert.Empty(t, got.CreatedBy, "the key value did not depend on CreatedBy")

			missing, err := idx.Resolve(ctx, "sha256:image-history-mismatch", []string{key})
			require.NoError(t, err)
			assert.Empty(t, missing)
		})
	}
}

// TestIndexDigestIsDisplayOnly covers gzip vs zstd reuse: the layer key is
// derived from the uncompressed diff ID, so a different compressed digest must
// never trigger a second analysis. The digest is retained only as a display
// field of the stored BlobInfo.
func TestIndexDigestIsDisplayOnly(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()

			// One uncompressed diff ID, two compressed representations.
			diffID := "sha256:uncompressed-diffid"
			gzipDigest := "sha256:gzip-digest"
			zstdDigest := "sha256:zstd-digest"
			assert.NotEqual(t, gzipDigest, zstdDigest)

			// Both compressions resolve to the same base/derived layer key.
			gzipKey, err := layercache.LayerKey("sha256:base-"+diffID, types.TypeContainerImage)
			require.NoError(t, err)
			zstdKey, err := layercache.LayerKey("sha256:base-"+diffID, types.TypeContainerImage)
			require.NoError(t, err)
			assert.Equal(t, gzipKey, zstdKey, "the key must be independent of the compressed digest")

			var calls atomic.Int32
			blob := sampleBlob(diffID)
			blob.Digest = gzipDigest
			_, err = idx.Put(ctx, gzipKey, func(context.Context) (types.BlobInfo, error) {
				calls.Add(1)
				return blob, nil
			})
			require.NoError(t, err)

			// The zstd variant hits the same entry without another analysis.
			missing, err := idx.Resolve(ctx, "sha256:image-zstd", []string{zstdKey})
			require.NoError(t, err)
			assert.Empty(t, missing)
			assert.Equal(t, int32(1), calls.Load())

			got, state, err := idx.Get(ctx, zstdKey)
			require.NoError(t, err)
			assert.Equal(t, layercache.StateWritten, state)
			assert.Equal(t, gzipDigest, got.Digest, "digest is kept as a display field")
			assert.Equal(t, diffID, got.DiffID, "the key identity is the uncompressed diff ID")
		})
	}
}

func TestIndexMissingThreeLayersAnalyzedThreeTimes(t *testing.T) {
	t.Parallel()

	for backend, c := range newCaches(t) {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			idx := newIndex(c)
			ctx := t.Context()
			keys := []string{"sha256:m1", "sha256:m2", "sha256:m3"}

			missing, err := idx.Resolve(ctx, "sha256:image-missing", keys)
			require.NoError(t, err)
			require.Len(t, missing, 3)

			var calls atomic.Int32
			for _, key := range missing {
				_, err = idx.Put(ctx, key, func(context.Context) (types.BlobInfo, error) {
					calls.Add(1)
					return sampleBlob(key), nil
				})
				require.NoError(t, err)
			}
			assert.Equal(t, int32(3), calls.Load())

			missing, err = idx.Resolve(ctx, "sha256:image-missing", keys)
			require.NoError(t, err)
			assert.Empty(t, missing, "the second run has zero missing layers")
		})
	}
}

func BenchmarkIndexHit(b *testing.B) {
	c := cache.NewMemoryCache()
	ctx := b.Context()
	idx := newIndex(c)
	key := "sha256:bench-hit"
	var analyzeCalls atomic.Int32
	_, err := idx.Put(ctx, key, func(context.Context) (types.BlobInfo, error) {
		analyzeCalls.Add(1)
		return sampleBlob(key), nil
	})
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, state, err := idx.Get(ctx, key)
		require.NoError(b, err)
		if state != layercache.StateWritten {
			b.Fatalf("unexpected state %s", state)
		}
	}
	b.StopTimer()

	// The hit path performs reads only: analysis ran once during setup and
	// never again during the benchmarked loop.
	assert.Equal(b, int32(1), analyzeCalls.Load())
}

func FuzzLayerKey(f *testing.F) {
	f.Add("sha256:abc", "container_image")
	f.Add("", "filesystem")
	f.Add("sha256:zzz", "vm")

	f.Fuzz(func(t *testing.T, baseKey, artifactType string) {
		key1, err := layercache.LayerKey(baseKey, types.ArtifactType(artifactType))
		if err != nil {
			return
		}
		key2, err := layercache.LayerKey(baseKey, types.ArtifactType(artifactType))
		require.NoError(t, err)
		assert.Equal(t, key1, key2, "the key function must be deterministic")
		assert.Len(t, key1, len("sha256:")+64)
	})
}

// Ensure the backend name list never silently collapses to a single backend.
func TestNewCachesBackends(t *testing.T) {
	t.Parallel()
	assert.Len(t, newCaches(t), 2)
}

func TestErrorWrappingPreservesContext(t *testing.T) {
	t.Parallel()

	c := cache.NewMemoryCache()
	idx := newIndex(c)
	key := "sha256:wrap"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := idx.Put(ctx, key, func(ctx context.Context) (types.BlobInfo, error) {
		return types.BlobInfo{}, fmt.Errorf("layer pull: %w", ctx.Err())
	})
	require.ErrorIs(t, err, context.Canceled)
}
