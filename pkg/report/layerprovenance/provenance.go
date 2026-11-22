// Package layerprovenance implements the opt-in "layer-provenance" report.
//
// The report records, for every vulnerability, the container image layer that
// introduced it and the semantic role of that layer (base, middle or
// application). The layer is taken from the observation made while scanning;
// it is never re-derived from file paths, which would be wrong when the same
// path exists in more than one layer.
//
// The report is a stream of JSON Lines records. Findings are encoded one at a
// time, so a large image does not require the whole document to be built in
// memory. A previous report can be supplied to produce a diff. Findings are
// identified by a hash of the package and vulnerability, which excludes the
// scan time, the image tag and the output order, so the same finding receives
// the same identity in both scans.
package layerprovenance

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

// SchemaVersion is the version of the report format. It is checked when a
// previous report is loaded.
const SchemaVersion = 1

// Record types emitted in the stream.
const (
	RecordTypeHeader       = "header"
	RecordTypeFinding      = "finding"
	RecordTypeLayerSummary = "layer_summary"
	RecordTypeSummary      = "summary"
)

// Status describes how a finding changed between two scans.
type Status string

const (
	StatusAdded     Status = "added"     // Present in the current scan only
	StatusRemoved   Status = "removed"   // Present in the previous scan only
	StatusUnchanged Status = "unchanged" // Present in both scans
)

// Header is the first record of a report.
type Header struct {
	Type          string        `json:"type"`
	SchemaVersion int           `json:"schemaVersion"`
	GeneratedBy   GeneratedBy   `json:"generatedBy"`
	Artifact      Artifact      `json:"artifact"`
	Previous      *PreviousInfo `json:"previous,omitempty"`
	Layers        []LayerInfo   `json:"layers"`
}

type GeneratedBy struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Artifact struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	ID   string `json:"id,omitempty"`
}

// PreviousInfo describes the report the diff was computed against.
type PreviousInfo struct {
	Path          string   `json:"path"`
	SchemaVersion int      `json:"schemaVersion"`
	Artifact      Artifact `json:"artifact"`
}

// LayerInfo identifies a layer and its role. Index is the position of the
// layer in the current image (Metadata.Layers), or -1 for a layer that exists
// only in the previous report.
type LayerInfo struct {
	Index  int              `json:"index"`
	Role   ftypes.LayerRole `json:"role"`
	Digest string           `json:"digest,omitempty"`
	DiffID string           `json:"diffID,omitempty"`
	Size   int64            `json:"size,omitempty"`
}

// Finding is one vulnerability in one package version, attributed to one
// layer. A vulnerability that affects several packages, or several layers,
// therefore produces several records.
type Finding struct {
	Type           string      `json:"type"`
	Status         Status      `json:"status"`
	Identity       string      `json:"identity"`
	Vulnerability  VulnInfo    `json:"vulnerability"`
	Package        PackageInfo `json:"package"`
	Class          string      `json:"class,omitempty"`
	TargetType     string      `json:"targetType,omitempty"`
	Layer          *LayerInfo  `json:"layer,omitempty"`
	PreviousLayers []LayerInfo `json:"previousLayers,omitempty"`
	LayerChanged   bool        `json:"layerChanged,omitempty"`
}

type VulnInfo struct {
	ID           string `json:"id"`
	Severity     string `json:"severity,omitempty"`
	FixedVersion string `json:"fixedVersion,omitempty"`
	Status       string `json:"status,omitempty"`
}

type PackageInfo struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
}

// Counts breaks a set of findings down by diff status.
type Counts struct {
	Total     int `json:"total"`
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Unchanged int `json:"unchanged"`
}

func (c *Counts) add(f Finding) {
	c.Total++
	switch f.Status {
	case StatusAdded:
		c.Added++
	case StatusRemoved:
		c.Removed++
	default:
		c.Unchanged++
	}
}

// LayerSummary reconciles the finding records with the layer they are
// attributed to. Each finding is attributed to exactly one layer: its current
// layer when it is present in the current scan, or its previous layer when it
// was removed. InCurrent/InPrevious say whether that layer is part of the
// respective image.
type LayerSummary struct {
	Type       string    `json:"type"`
	Layer      LayerInfo `json:"layer"`
	InCurrent  bool      `json:"inCurrent"`
	InPrevious bool      `json:"inPrevious"`
	Findings   Counts    `json:"findings"`
}

// FindingBreakdown is the total breakdown, including findings whose layer
// changed between the two scans.
type FindingBreakdown struct {
	Counts
	LayerChanged int `json:"layerChanged"`
}

// Summary is the last record of a report. ByRole groups the counts by the role
// of the layer each finding was attributed to, which shows whether a change
// concentrates in the base image or in the application layers.
type Summary struct {
	Type       string            `json:"type"`
	Findings   FindingBreakdown  `json:"findings"`
	ByRole     map[string]Counts `json:"byRole"`
	Reconciled bool              `json:"reconciled"`
}

// layerIndex resolves layer identity to an index and role.
type layerIndex struct {
	byDiffID map[string]LayerInfo
	byDigest map[string]LayerInfo
	all      []LayerInfo
}

func newLayerIndex(report types.Report) *layerIndex {
	idx := &layerIndex{
		byDiffID: make(map[string]LayerInfo),
		byDigest: make(map[string]LayerInfo),
	}
	var roles []ftypes.LayerRole
	if p := report.LayerProvenance; p != nil {
		roles = p.Roles
	}
	idx.all = make([]LayerInfo, 0, len(report.Metadata.Layers))
	for i, l := range report.Metadata.Layers {
		role := ftypes.LayerRoleUnknown
		if i < len(roles) {
			role = roles[i]
		}
		info := LayerInfo{
			Index:  i,
			Role:   role,
			Digest: l.Digest,
			DiffID: l.DiffID,
			Size:   l.Size,
		}
		idx.all = append(idx.all, info)
		if l.DiffID != "" {
			idx.byDiffID[l.DiffID] = info
		}
		if l.Digest != "" {
			idx.byDigest[l.Digest] = info
		}
	}
	return idx
}

// lookup resolves a vulnerability's layer. The uncompressed layer ID is the
// canonical identity; the compressed digest is only a fallback.
func (idx *layerIndex) lookup(l ftypes.Layer) (LayerInfo, bool) {
	if l.DiffID != "" {
		if info, ok := idx.byDiffID[l.DiffID]; ok {
			return info, true
		}
	}
	if l.Digest != "" {
		if info, ok := idx.byDigest[l.Digest]; ok {
			return info, true
		}
	}
	return LayerInfo{}, false
}

// unknownLayer is used when a vulnerability carries no layer information, e.g.
// for packages merged from the image configuration rather than from a layer.
func unknownLayer() LayerInfo {
	return LayerInfo{Index: -1, Role: ftypes.LayerRoleUnknown}
}

// identity is the stable identity of a finding. It is derived only from data
// that is the same in every scan of the same image and package set: it does
// not include the scan time, the image tag, the layer or the output order.
func identity(class, targetType string, v types.DetectedVulnerability) string {
	key := struct {
		Class           string `json:"class"`
		TargetType      string `json:"targetType"`
		VulnerabilityID string `json:"vulnerabilityID"`
		PkgID           string `json:"pkgID"`
		PkgName         string `json:"pkgName"`
		PkgPath         string `json:"pkgPath"`
		Installed       string `json:"installedVersion"`
	}{
		Class:           class,
		TargetType:      targetType,
		VulnerabilityID: v.VulnerabilityID,
		PkgID:           v.PkgID,
		PkgName:         v.PkgName,
		PkgPath:         v.PkgPath,
		Installed:       v.InstalledVersion,
	}
	b, _ := json.Marshal(key) // A struct of strings never fails to marshal.
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func vulnInfo(v types.DetectedVulnerability) VulnInfo {
	return VulnInfo{
		ID:           v.VulnerabilityID,
		Severity:     v.Severity,
		FixedVersion: v.FixedVersion,
		Status:       v.Status.String(),
	}
}

func pkgInfo(v types.DetectedVulnerability) PackageInfo {
	return PackageInfo{
		ID:      v.PkgID,
		Name:    v.PkgName,
		Version: v.InstalledVersion,
		Path:    v.PkgPath,
	}
}

// sortFindings orders records deterministically, independent of the order in
// which the scanner produced them.
func sortFindings(findings []Finding) {
	slices.SortFunc(findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.Status, b.Status),
			cmp.Compare(a.Class, b.Class),
			cmp.Compare(a.TargetType, b.TargetType),
			cmp.Compare(a.Package.Name, b.Package.Name),
			cmp.Compare(a.Package.Version, b.Package.Version),
			cmp.Compare(a.Package.Path, b.Package.Path),
			cmp.Compare(a.Package.ID, b.Package.ID),
			cmp.Compare(a.Vulnerability.ID, b.Vulnerability.ID),
			cmp.Compare(layerSortKey(a.Layer), layerSortKey(b.Layer)),
			cmp.Compare(previousLayersSortKey(a.PreviousLayers), previousLayersSortKey(b.PreviousLayers)),
			cmp.Compare(a.Identity, b.Identity),
		)
	})
}

func layerSortKey(l *LayerInfo) string {
	if l == nil {
		return ""
	}
	return layerIdentity(*l)
}

// layerIdentity is the stable key of a layer. The index alone is not enough:
// a layer can be absent from the current image (removed findings) and the same
// diff ID can appear at a different position after a rebuild.
func layerIdentity(l LayerInfo) string {
	return fmt.Sprintf("%s/%s", l.DiffID, l.Digest)
}

// sortLayerSummary orders layer summaries deterministically.
func sortLayerSummary(ls []LayerSummary) {
	slices.SortFunc(ls, func(a, b LayerSummary) int {
		return cmp.Or(
			cmp.Compare(a.Layer.Index, b.Layer.Index),
			cmp.Compare(a.Layer.DiffID, b.Layer.DiffID),
			cmp.Compare(a.Layer.Digest, b.Layer.Digest),
		)
	})
}

func previousLayersSortKey(ls []LayerInfo) string {
	keys := make([]string, len(ls))
	for i, l := range ls {
		keys[i] = layerSortKey(&l)
	}
	slices.Sort(keys)
	return strings.Join(keys, ",")
}

// headerFrom builds the header record for a report.
func headerFrom(report types.Report, prev *Previous) Header {
	h := Header{
		Type:          RecordTypeHeader,
		SchemaVersion: SchemaVersion,
		GeneratedBy: GeneratedBy{
			Name:    "trivy",
			Version: app.Version(),
		},
		Artifact: Artifact{
			Name: report.ArtifactName,
			Type: string(report.ArtifactType),
			ID:   report.ArtifactID,
		},
	}
	if prev != nil {
		h.Previous = &PreviousInfo{
			Path:          prev.Path,
			SchemaVersion: prev.SchemaVersion,
			Artifact: Artifact{
				Name: prev.Report.ArtifactName,
				Type: string(prev.Report.ArtifactType),
				ID:   prev.Report.ArtifactID,
			},
		}
	}
	for _, info := range newLayerIndex(report).all {
		h.Layers = append(h.Layers, info)
	}
	return h
}

// roleOf returns the role of the layer a finding is attributed to: its current
// layer for findings present in the current scan, and its previous layer for
// removed findings, which no longer have a current layer.
func roleOf(f Finding) ftypes.LayerRole {
	if f.Status == StatusRemoved {
		if len(f.PreviousLayers) > 0 {
			return f.PreviousLayers[0].Role
		}
		return ftypes.LayerRoleUnknown
	}
	if f.Layer != nil {
		return f.Layer.Role
	}
	return ftypes.LayerRoleUnknown
}
