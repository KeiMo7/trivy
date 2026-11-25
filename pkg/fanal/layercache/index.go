package layercache

import (
	"context"
	"errors"
	"slices"
	"sync"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// State represents the lifecycle state of a layer entry in the index.
type State int

const (
	// StateAbsent means no usable entry can be retrieved for the key.
	StateAbsent State = iota
	// StateInflight means an analysis has been registered but not committed yet.
	StateInflight
	// StateWritten means an entry is available with a matching schema version.
	StateWritten
	// StateStale means an entry exists but its schema version does not match or
	// its payload cannot be parsed.
	StateStale
)

// String returns the textual representation of the state.
func (s State) String() string {
	switch s {
	case StateAbsent:
		return "absent"
	case StateInflight:
		return "inflight"
	case StateWritten:
		return "written"
	case StateStale:
		return "stale"
	default:
		return "unknown"
	}
}

// Index resolves layer keys against the underlying cache and deduplicates
// concurrent analysis of the same layer.
//
// An Index is scoped to a single scan. It must not be reused across scans,
// otherwise inflight keys of a previous image could pollute the missing layer
// detection of the next one.
type Index interface {
	// Resolve returns the layer keys that have to be analyzed. Duplicate keys
	// are collapsed, so an image referencing the same diff ID several times
	// reports the key only once. A stale or unreadable entry counts as missing
	// without returning an error.
	Resolve(ctx context.Context, imageKey string, layerKeys []string) ([]string, error)

	// Get returns the cached blob together with its state. A stale or unreadable
	// entry is reported with StateStale, a missing entry with StateAbsent.
	Get(ctx context.Context, layerKey string) (types.BlobInfo, State, error)

	// Put ensures that analyze runs at most once for the given layer key. The
	// first caller becomes the holder, performs the analysis and commits the
	// result. Concurrent callers wait for the holder and receive the same
	// BlobInfo. On cancellation the inflight entry is released and waiters
	// observe the same error.
	Put(ctx context.Context, layerKey string, analyze func(context.Context) (types.BlobInfo, error)) (types.BlobInfo, error)
}

// Option configures an Index.
type Option func(*index)

// WithLogger overrides the default logger.
func WithLogger(logger *log.Logger) Option {
	return func(i *index) {
		if logger != nil {
			i.logger = logger
		}
	}
}

// inflight is the registration of an in-progress analysis for one layer key.
type inflight struct {
	done chan struct{}
	once sync.Once

	blob types.BlobInfo
	err  error
}

type index struct {
	cache  cache.Cache
	logger *log.Logger

	mu      sync.Mutex
	pending map[string]*inflight
}

var _ Index = (*index)(nil)

// New creates an Index over the given cache. The index keeps no state across
// scans and the inflight table is empty at construction.
func New(c cache.Cache, opts ...Option) Index {
	i := &index{
		cache:   c,
		logger:  log.WithPrefix("layercache"),
		pending: make(map[string]*inflight),
	}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

// Resolve collapses duplicates and reports the keys that must be analyzed.
func (i *index) Resolve(ctx context.Context, imageKey string, layerKeys []string) ([]string, error) {
	uniqueKeys := make([]string, 0, len(layerKeys))
	for _, key := range layerKeys {
		if !slices.Contains(uniqueKeys, key) {
			uniqueKeys = append(uniqueKeys, key)
		}
	}

	missing := make([]string, 0, len(uniqueKeys))
	for _, key := range uniqueKeys {
		_, state, err := i.Get(ctx, key)
		if err != nil {
			return nil, xerrors.Errorf("resolve layer (%s) of image (%s): %w", key, imageKey, err)
		}
		if state != StateWritten {
			missing = append(missing, key)
		}
	}
	return missing, nil
}

// Get inspects the state of one layer key.
func (i *index) Get(ctx context.Context, layerKey string) (types.BlobInfo, State, error) {
	i.mu.Lock()
	if entry, ok := i.pending[layerKey]; ok {
		i.mu.Unlock()

		// Registered but not committed yet.
		select {
		case <-entry.done:
		default:
			return types.BlobInfo{}, StateInflight, nil
		}
	} else {
		i.mu.Unlock()
	}

	blob, err := i.cache.GetBlob(ctx, layerKey)
	if err != nil {
		if errors.Is(err, cache.ErrBlobNotFound) {
			return types.BlobInfo{}, StateAbsent, nil
		}
		// A parse failure or any other storage error means the stored entry
		// cannot be trusted. It is treated as stale, i.e. re-analyzable.
		i.logger.Debug("Stale blob entry detected", log.String("layer_key", layerKey), log.Err(err))
		return types.BlobInfo{}, StateStale, nil
	}

	if blob.SchemaVersion != types.BlobJSONSchemaVersion {
		i.logger.Debug("Blob schema version mismatch",
			log.String("layer_key", layerKey),
			log.Int("cached_schema_version", blob.SchemaVersion),
			log.Int("current_schema_version", types.BlobJSONSchemaVersion))
		return blob, StateStale, nil
	}
	return blob, StateWritten, nil
}

// Put single-flights the analysis of one layer key.
func (i *index) Put(ctx context.Context, layerKey string,
	analyze func(context.Context) (types.BlobInfo, error),
) (types.BlobInfo, error) {
	if analyze == nil {
		return types.BlobInfo{}, xerrors.Errorf("analyze function is nil for layer (%s)", layerKey)
	}

	i.mu.Lock()
	if entry, ok := i.pending[layerKey]; ok {
		// Another caller already registered the analysis. Waiters never
		// re-register a key, so a failed holder cannot trigger a second
		// concurrent analysis.
		i.mu.Unlock()
		return i.wait(ctx, layerKey, entry)
	}

	entry := &inflight{done: make(chan struct{})}
	i.pending[layerKey] = entry
	i.mu.Unlock()

	blob, err := analyze(ctx)
	if err != nil {
		// Release the registration so a later attempt can try again and no
		// half-written entry remains. Waiters observe the same error.
		i.fail(layerKey, entry, xerrors.Errorf("analyze layer (%s): %w", layerKey, err))
		return types.BlobInfo{}, entry.err
	}

	// Normalize the schema version on write so Resolve/Get observe StateWritten.
	if blob.SchemaVersion == 0 {
		blob.SchemaVersion = types.BlobJSONSchemaVersion
	}

	if err = i.cache.PutBlob(ctx, layerKey, blob); err != nil {
		i.fail(layerKey, entry, xerrors.Errorf("store layer (%s): %w", layerKey, err))
		return types.BlobInfo{}, entry.err
	}

	entry.blob = blob
	// Keep the entry registered and only close the channel. Deleting it here
	// would open a window in which a new caller cannot observe the inflight
	// registration and would start a second analysis. A completed entry is
	// recognized as committed by Get.
	entry.close()

	return blob, nil
}

// close signals completion to waiters exactly once.
func (e *inflight) close() {
	e.once.Do(func() { close(e.done) })
}

// wait blocks until the holder finishes or the caller's context is done.
func (i *index) wait(ctx context.Context, layerKey string, entry *inflight) (types.BlobInfo, error) {
	select {
	case <-entry.done:
		if entry.err != nil {
			return types.BlobInfo{}, xerrors.Errorf("wait for layer (%s): %w", layerKey, entry.err)
		}
		return entry.blob, nil
	case <-ctx.Done():
		return types.BlobInfo{}, xerrors.Errorf("wait for layer (%s): %w", layerKey, ctx.Err())
	}
}

// fail marks an inflight entry as failed and removes it from the registry.
// Only the holder that created the entry removes it; waiters are woken through
// channel close with the error preserved so they converge on the same failure.
func (i *index) fail(layerKey string, entry *inflight, err error) {
	entry.err = err

	i.mu.Lock()
	if current, ok := i.pending[layerKey]; ok && current == entry {
		delete(i.pending, layerKey)
	}
	i.mu.Unlock()

	entry.close()
}

// CommitArtifact writes the image artifact entry after every missing layer has
// been committed. It must be called only when all layer writes succeeded;
// otherwise the next scan still considers the image missing.
func (i *index) CommitArtifact(ctx context.Context, imageKey string, info types.ArtifactInfo) error {
	if err := i.cache.PutArtifact(ctx, imageKey, info); err != nil {
		return xerrors.Errorf("commit artifact (%s): %w", imageKey, err)
	}
	return nil
}

// inflightCount returns the number of registered analyses. It is intended for
// tests and bounded-memory assertions.
func (i *index) inflightCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.pending)
}

// Reset releases every inflight registration and clears the index. It is
// called at the end of a scan so the inflight table never grows beyond the
// distinct layer count of one scan and cannot pollute another scan.
func (i *index) Reset() {
	i.mu.Lock()
	defer i.mu.Unlock()

	for key, entry := range i.pending {
		entry.err = context.Canceled
		entry.close()
		delete(i.pending, key)
	}
}

// ArtifactState reports whether the artifact entry of the given image is
// committed. A missing or unreadable entry yields StateAbsent, so callers can
// decide whether the image configuration has to be recomputed while preserving
// the layer missing list.
func (i *index) ArtifactState(ctx context.Context, imageKey string) (types.ArtifactInfo, State, error) {
	info, err := i.cache.GetArtifact(ctx, imageKey)
	if err != nil {
		if errors.Is(err, cache.ErrArtifactNotFound) {
			return types.ArtifactInfo{}, StateAbsent, nil
		}
		i.logger.Debug("Stale artifact entry detected", log.String("image_key", imageKey), log.Err(err))
		return types.ArtifactInfo{}, StateAbsent, nil
	}
	if info.SchemaVersion != types.ArtifactJSONSchemaVersion {
		i.logger.Debug("Artifact schema version mismatch",
			log.String("image_key", imageKey),
			log.Int("cached_schema_version", info.SchemaVersion),
			log.Int("current_schema_version", types.ArtifactJSONSchemaVersion))
		return info, StateStale, nil
	}
	return info, StateWritten, nil
}
