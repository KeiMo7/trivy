package applier

import (
	"cmp"
	"slices"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
)

// provenanceKeys indexes provenance records for lookup.
type provenanceKeys struct {
	// osPkg is keyed by the package database file path and the package identity.
	osPkg map[string]ftypes.PackageProvenance
	// libPkg is keyed by the application file path, type and package identity.
	libPkg map[string]ftypes.PackageProvenance
}

// originRecorder records the origin layer of packages while ApplyLayers walks
// the layers from the bottom to the top. Because each write replaces the
// previous value, the last write wins: that is the layer that actually
// provided the effective file. This differs from the path-based lookup, which
// can return a lower layer whose entry was overwritten.
type originRecorder struct {
	enabled bool
	keys    provenanceKeys
}

func newOriginRecorder(enabled bool) *originRecorder {
	return &originRecorder{
		enabled: enabled,
		keys: provenanceKeys{
			osPkg:  make(map[string]ftypes.PackageProvenance),
			libPkg: make(map[string]ftypes.PackageProvenance),
		},
	}
}

func osPkgKey(filePath, pkgID, name, version string) string {
	return strings.Join([]string{filePath, cmp.Or(pkgID, name+"\x00"+version), name, version}, "\x00")
}

func libPkgKey(filePath, kind, pkgID, name, version string) string {
	return strings.Join([]string{filePath, kind, cmp.Or(pkgID, name+"\x00"+version), name, version}, "\x00")
}

func provenanceLayer(layer ftypes.BlobInfo) ftypes.Layer {
	return ftypes.Layer{
		Digest:    layer.Digest,
		DiffID:    layer.DiffID,
		CreatedBy: layer.CreatedBy,
	}
}

func (r *originRecorder) recordPackages(layer ftypes.BlobInfo, info ftypes.PackageInfo) {
	if !r.enabled {
		return
	}
	l := provenanceLayer(layer)
	for _, pkg := range info.Packages {
		r.keys.osPkg[osPkgKey(info.FilePath, pkg.ID, pkg.Name, utils.FormatVersion(pkg))] = ftypes.PackageProvenance{
			Kind:     "os",
			PkgID:    pkg.ID,
			Name:     pkg.Name,
			Version:  utils.FormatVersion(pkg),
			FilePath: info.FilePath,
			Layer:    l,
		}
	}
}

func (r *originRecorder) recordApplication(layer ftypes.BlobInfo, app ftypes.Application) {
	if !r.enabled {
		return
	}
	l := provenanceLayer(layer)
	for _, pkg := range app.Packages {
		r.keys.libPkg[libPkgKey(app.FilePath, string(app.Type), pkg.ID, pkg.Name, pkg.Version)] = ftypes.PackageProvenance{
			Kind:     string(app.Type),
			PkgID:    pkg.ID,
			Name:     pkg.Name,
			Version:  pkg.Version,
			FilePath: app.FilePath,
			PkgPath:  pkg.FilePath,
			Layer:    l,
		}
	}
}

// deleteByPrefix removes provenance for files deleted by a whiteout or an
// opaque directory. A key is "<file path>\x00<package identity>", so a record
// is matched when its file path equals the removed path (whiteout of a file)
// or is nested under it (opaque directory). A plain string prefix is not
// enough: "app/foo" must not match "app/foobar".
func (r *originRecorder) deleteByPrefix(path string) {
	if !r.enabled {
		return
	}
	exact := path + "\x00"
	nested := path + "/"
	match := func(k string) bool {
		return strings.HasPrefix(k, exact) || strings.HasPrefix(k, nested)
	}
	for k := range r.keys.osPkg {
		if match(k) {
			delete(r.keys.osPkg, k)
		}
	}
	for k := range r.keys.libPkg {
		if match(k) {
			delete(r.keys.libPkg, k)
		}
	}
}

// result returns the recorded provenance sorted by layer and package, so that
// the result is deterministic regardless of map iteration order.
func (r *originRecorder) result() []ftypes.PackageProvenance {
	if !r.enabled {
		return nil
	}
	out := make([]ftypes.PackageProvenance, 0, len(r.keys.osPkg)+len(r.keys.libPkg))
	for _, p := range r.keys.osPkg {
		out = append(out, p)
	}
	for _, p := range r.keys.libPkg {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b ftypes.PackageProvenance) int {
		return cmp.Or(
			cmp.Compare(a.Layer.DiffID, b.Layer.DiffID),
			cmp.Compare(a.Layer.Digest, b.Layer.Digest),
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.FilePath, b.FilePath),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.PkgID, b.PkgID),
		)
	})
	return out
}
