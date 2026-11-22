package applier_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// provenanceByPkg indexes provenance records by package name and version.
func provenanceByPkg(detail ftypes.ArtifactDetail) map[string]ftypes.PackageProvenance {
	out := make(map[string]ftypes.PackageProvenance, len(detail.Provenance))
	for _, p := range detail.Provenance {
		out[p.Name+"@"+p.Version] = p
	}
	return out
}

// TestApplyLayersWithProvenance_SamePathInMultipleLayers checks that when the
// same package database file path appears in more than one layer, the package
// is attributed to the layer that actually provided the effective entry, not
// to a lower layer whose entry was overwritten.
func TestApplyLayersWithProvenance_SamePathInMultipleLayers(t *testing.T) {
	layers := []ftypes.BlobInfo{
		{
			Digest: "sha256:base-digest",
			DiffID: "sha256:base-diff",
			PackageInfos: []ftypes.PackageInfo{
				{
					FilePath: "lib/apk/db/installed",
					Packages: ftypes.Packages{
						{Name: "openssl", Version: "1.0.0", Release: "r0"},
						{Name: "musl", Version: "1.0.0", Release: "r0"},
					},
				},
			},
		},
		{
			Digest: "sha256:app-digest",
			DiffID: "sha256:app-diff",
			PackageInfos: []ftypes.PackageInfo{
				{
					// Same path as the base layer and the same package identity:
					// the application layer rewrites the database. The effective
					// entry is the one in this layer.
					FilePath: "lib/apk/db/installed",
					Packages: ftypes.Packages{
						{Name: "openssl", Version: "1.0.0", Release: "r0"},
						{Name: "musl", Version: "2.0.0", Release: "r0"},
					},
				},
			},
		},
	}

	got := applier.ApplyLayersWithProvenance(layers)
	require.NotEmpty(t, got.Provenance)

	byPkg := provenanceByPkg(got)
	require.Contains(t, byPkg, "openssl@1.0.0-r0")
	require.Contains(t, byPkg, "musl@2.0.0-r0")
	// Both packages are provided by the rewritten database in the application
	// layer, so that is where the effective entries live. The path-based
	// lookup would return the base layer because it is the first match.
	assert.Equal(t, "sha256:app-diff", byPkg["openssl@1.0.0-r0"].Layer.DiffID)
	assert.Equal(t, "sha256:app-diff", byPkg["musl@2.0.0-r0"].Layer.DiffID)

	// The regular lookup still reports the lower layer; provenance is recorded
	// alongside it without changing the existing result.
	var openssl *ftypes.Package
	for i := range got.Packages {
		if got.Packages[i].Name == "openssl" {
			openssl = &got.Packages[i]
		}
	}
	require.NotNil(t, openssl)
	assert.Equal(t, "sha256:base-diff", openssl.Layer.DiffID)
}

// TestApplyLayers_NoProvenanceByDefault checks that the plain ApplyLayers does
// not populate provenance, so existing callers and outputs are unaffected.
func TestApplyLayers_NoProvenanceByDefault(t *testing.T) {
	layers := []ftypes.BlobInfo{
		{
			Digest: "sha256:base-digest",
			DiffID: "sha256:base-diff",
			PackageInfos: []ftypes.PackageInfo{
				{FilePath: "lib/apk/db/installed", Packages: ftypes.Packages{{Name: "openssl", Version: "1.0.0"}}},
			},
		},
	}
	got := applier.ApplyLayers(layers)
	assert.Empty(t, got.Provenance)
}

// TestApplyLayersWithProvenance_MultiLayerLibrary checks the same attribution
// rule for language-specific packages: a lock file present in more than one
// layer must be attributed to the layer that provided the effective content.
func TestApplyLayersWithProvenance_MultiLayerLibrary(t *testing.T) {
	layers := []ftypes.BlobInfo{
		{
			Digest: "sha256:base-digest",
			DiffID: "sha256:base-diff",
			Applications: []ftypes.Application{
				{
					Type:     ftypes.Bundler,
					FilePath: "app/Gemfile.lock",
					Packages: ftypes.Packages{{Name: "rails", Version: "5.0.0"}},
				},
			},
		},
		{
			Digest: "sha256:app-digest",
			DiffID: "sha256:app-diff",
			Applications: []ftypes.Application{
				{
					Type:     ftypes.Bundler,
					FilePath: "app/Gemfile.lock",
					Packages: ftypes.Packages{{Name: "rails", Version: "6.0.0"}},
				},
			},
		},
	}

	got := applier.ApplyLayersWithProvenance(layers)
	byPkg := provenanceByPkg(got)
	require.Contains(t, byPkg, "rails@6.0.0")
	assert.Equal(t, "sha256:app-diff", byPkg["rails@6.0.0"].Layer.DiffID)
}

// TestApplyLayersWithProvenance_Whiteout checks that provenance for a file
// removed by a whiteout is not kept: the package is no longer provided by that
// layer.
func TestApplyLayersWithProvenance_Whiteout(t *testing.T) {
	layers := []ftypes.BlobInfo{
		{
			Digest: "sha256:base-digest",
			DiffID: "sha256:base-diff",
			PackageInfos: []ftypes.PackageInfo{
				{FilePath: "app/package-lock.json", Packages: ftypes.Packages{{Name: "lodash", Version: "4.17.0"}}},
				// A sibling path that shares the removed file's prefix must be kept.
				{FilePath: "app/package-lock.json.bak", Packages: ftypes.Packages{{Name: "left-pad", Version: "1.0.0"}}},
			},
		},
		{
			Digest:        "sha256:app-digest",
			DiffID:        "sha256:app-diff",
			WhiteoutFiles: []string{"app/package-lock.json"},
		},
	}

	got := applier.ApplyLayersWithProvenance(layers)
	byPkg := provenanceByPkg(got)
	assert.NotContains(t, byPkg, "lodash@4.17.0")

	// A sibling path that merely shares a prefix must not be removed.
	assert.Contains(t, byPkg, "left-pad@1.0.0")
}
