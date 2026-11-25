package cache

import "golang.org/x/xerrors"

// Sentinel errors used to distinguish a cache miss from a corrupted entry.
// Callers can use errors.Is to detect an absent entry, while a JSON parse
// failure or any other storage error means the stored entry is stale.
var (
	// ErrBlobNotFound is returned when a blob entry is not present in the cache.
	ErrBlobNotFound = xerrors.New("blob not found in cache")

	// ErrArtifactNotFound is returned when an artifact entry is not present in the cache.
	ErrArtifactNotFound = xerrors.New("artifact not found in cache")
)
