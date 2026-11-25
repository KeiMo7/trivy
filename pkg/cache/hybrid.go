package cache

import (
	"context"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var _ Cache = (*HybridCache)(nil)

// HybridCache combines a local bbolt cache with a remote cache backend such as
// Redis.
//
// The remote backend only implements the four ArtifactCache methods. Reads of
// blobs and artifacts (GetBlob/GetArtifact) always go to the local bbolt cache,
// so a remote outage or a failed remote write never invalidates locally
// computed results. Remote write failures are downgraded to a single warning;
// remote delete failures are aggregated with multierror and returned.
type HybridCache struct {
	local  LocalArtifactCache
	remote ArtifactCache

	logger *log.Logger
}

// HybridOption configures a HybridCache.
type HybridOption func(*HybridCache)

// WithHybridLogger overrides the default hybrid cache logger.
func WithHybridLogger(logger *log.Logger) HybridOption {
	return func(c *HybridCache) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// NewHybridCache builds a cache whose authoritative reads are local and whose
// ArtifactCache operations are mirrored to the remote backend.
func NewHybridCache(local LocalArtifactCache, remote ArtifactCache, opts ...HybridOption) *HybridCache {
	c := &HybridCache{
		local:  local,
		remote: remote,
		logger: log.WithPrefix("cache"),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// MissingBlobs is served by the remote backend, which owns cross-host
// knowledge of which blobs and artifacts have already been analyzed.
func (c *HybridCache) MissingBlobs(ctx context.Context, artifactID string, blobIDs []string) (bool, []string, error) {
	missingArtifact, missingBlobIDs, err := c.remote.MissingBlobs(ctx, artifactID, blobIDs)
	if err != nil {
		return false, nil, xerrors.Errorf("remote MissingBlobs: %w", err)
	}
	return missingArtifact, missingBlobIDs, nil
}

// PutArtifact writes to the local bbolt cache first, then mirrors to the remote
// backend. A remote failure only produces a warning; the local entry stands.
func (c *HybridCache) PutArtifact(ctx context.Context, artifactID string, artifactInfo types.ArtifactInfo) error {
	if lc, ok := c.local.(ArtifactCache); ok {
		if err := lc.PutArtifact(ctx, artifactID, artifactInfo); err != nil {
			return xerrors.Errorf("local PutArtifact (%s): %w", artifactID, err)
		}
	}
	if err := c.remote.PutArtifact(ctx, artifactID, artifactInfo); err != nil {
		c.logger.Warn("Failed to store artifact in the remote cache; using the local cache",
			log.String("artifact_id", artifactID), log.Err(err))
	}
	return nil
}

// PutBlob writes to the local bbolt cache first, then mirrors to the remote
// backend. A remote failure only produces a warning and never discards the
// locally written result.
func (c *HybridCache) PutBlob(ctx context.Context, blobID string, blobInfo types.BlobInfo) error {
	if lc, ok := c.local.(ArtifactCache); ok {
		if err := lc.PutBlob(ctx, blobID, blobInfo); err != nil {
			return xerrors.Errorf("local PutBlob (%s): %w", blobID, err)
		}
	}
	if err := c.remote.PutBlob(ctx, blobID, blobInfo); err != nil {
		c.logger.Warn("Failed to store blob in the remote cache; using the local cache",
			log.String("blob_id", blobID), log.Err(err))
	}
	return nil
}

// DeleteBlobs removes entries from both backends. A partial failure is
// aggregated into a multierror instead of being silently dropped.
func (c *HybridCache) DeleteBlobs(ctx context.Context, blobIDs []string) error {
	var errs error

	if lc, ok := c.local.(ArtifactCache); ok {
		if err := lc.DeleteBlobs(ctx, blobIDs); err != nil {
			errs = multierror.Append(errs, xerrors.Errorf("local DeleteBlobs: %w", err))
		}
	}
	if err := c.remote.DeleteBlobs(ctx, blobIDs); err != nil {
		errs = multierror.Append(errs, xerrors.Errorf("remote DeleteBlobs: %w", err))
	}
	return errs
}

// GetArtifact reads only from the local bbolt cache.
func (c *HybridCache) GetArtifact(ctx context.Context, artifactID string) (types.ArtifactInfo, error) {
	return c.local.GetArtifact(ctx, artifactID)
}

// GetBlob reads only from the local bbolt cache.
func (c *HybridCache) GetBlob(ctx context.Context, blobID string) (types.BlobInfo, error) {
	return c.local.GetBlob(ctx, blobID)
}

// Close closes the local database.
func (c *HybridCache) Close() error {
	return c.local.Close()
}

// Clear clears the local database.
func (c *HybridCache) Clear(ctx context.Context) error {
	return c.local.Clear(ctx)
}
