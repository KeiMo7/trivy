// Package layercache provides an in-process index over the blob bucket of
// pkg/cache. It resolves layer keys for a given image, tracks the lifecycle
// state of each entry and deduplicates concurrent analysis of the same layer
// (single-flight).
//
// The package never changes the on-disk key format produced by cache.CalcKey:
// LayerKey takes the CalcKey output as its base and only applies an additional
// sha256 digest that folds in the de-duplication strategy version, the layer
// ordering version and the artifact type. Artifact types therefore never share
// entries, while layers of the same artifact type keep sharing entries across
// images through their uncompressed diff IDs.
package layercache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const (
	// dedupStrategyVersion is bumped when the semantics of layer merging or
	// de-duplication change in an incompatible way.
	dedupStrategyVersion = 1

	// layerOrderingVersion is bumped when the relative ordering semantics of
	// layers inside an image change.
	layerOrderingVersion = 1

	sha256Prefix = "sha256:"
)

// keyMaterial is serialized with a fixed field order so that the digest is
// deterministic across processes and Go versions.
type keyMaterial struct {
	BaseKey              string             `json:"base_key"`
	DedupStrategyVersion int                `json:"dedup_strategy_version"`
	LayerOrderingVersion int                `json:"layer_ordering_version"`
	ArtifactType         types.ArtifactType `json:"artifact_type"`
}

// LayerKey derives the index layer key from a base key produced by
// cache.CalcKey. The base key itself is computed from the uncompressed layer
// diff ID, so a different compressed digest (gzip vs zstd) never produces a
// different layer key.
//
// The digest folds in the de-duplication strategy version, the layer ordering
// version and the artifact type with a fixed JSON field encoding order.
func LayerKey(baseKey string, artifactType types.ArtifactType) (string, error) {
	material := keyMaterial{
		BaseKey:              baseKey,
		DedupStrategyVersion: dedupStrategyVersion,
		LayerOrderingVersion: layerOrderingVersion,
		ArtifactType:         artifactType,
	}

	b, err := json.Marshal(material)
	if err != nil {
		return "", xerrors.Errorf("marshal layer key material: %w", err)
	}

	sum := sha256.Sum256(b)
	return fmt.Sprintf("%s%s", sha256Prefix, hex.EncodeToString(sum[:])), nil
}
