package layerprovenance_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/layerprovenance"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	baseDiffID = "sha256:base-layer"
	midDiffID  = "sha256:middle-layer"
	appDiffID  = "sha256:app-layer"
)

func testLayers() ftypes.Layers {
	return ftypes.Layers{
		{Size: 100, Digest: "sha256:base-digest", DiffID: baseDiffID},
		{Size: 200, Digest: "sha256:mid-digest", DiffID: midDiffID},
		{Size: 300, Digest: "sha256:app-digest", DiffID: appDiffID},
	}
}

func testProvenance() *types.LayerProvenance {
	return &types.LayerProvenance{
		Roles: []ftypes.LayerRole{
			ftypes.LayerRoleBase,
			ftypes.LayerRoleMiddle,
			ftypes.LayerRoleApplication,
		},
	}
}

func vuln(id, pkg, version, layerDiffID string) types.DetectedVulnerability {
	return types.DetectedVulnerability{
		VulnerabilityID:  id,
		PkgID:            pkg + "@" + version,
		PkgName:          pkg,
		InstalledVersion: version,
		Status:           dbTypes.StatusFixed,
		Layer:            ftypes.Layer{DiffID: layerDiffID},
		Vulnerability:    dbTypes.Vulnerability{Severity: "HIGH"},
	}
}

func testReport(vulns ...types.DetectedVulnerability) types.Report {
	r := types.Report{
		ArtifactName: "example:latest",
		ArtifactType: ftypes.TypeContainerImage,
		Metadata: types.Metadata{
			Layers: testLayers(),
		},
		Results: types.Results{
			{
				Target:          "example (alpine 3.19)",
				Class:           types.ClassOSPkg,
				Type:            ftypes.Alpine,
				Vulnerabilities: vulns,
			},
		},
	}
	return r
}

func withProvenance(r types.Report) types.Report {
	r.LayerProvenance = testProvenance()
	return r
}

func write(t *testing.T, r types.Report, prev *layerprovenance.Previous) string {
	t.Helper()
	var buf bytes.Buffer
	w := layerprovenance.NewWriter(layerprovenance.Options{Output: &buf, Previous: prev})
	require.NoError(t, w.Write(t.Context(), r))
	return buf.String()
}

// loadPrevious parses the output of a previous run so it can be used as input
// to the diff, exercising the same loader the CLI uses.
func loadPrevious(t *testing.T, content string) *layerprovenance.Previous {
	t.Helper()
	path := filepath.Join(t.TempDir(), "prev.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	prev, err := layerprovenance.LoadPrevious(path)
	require.NoError(t, err)
	return prev
}

// records decodes a report stream into typed records.
type records struct {
	Header       layerprovenance.Header
	Findings     []layerprovenance.Finding
	LayerSummary []layerprovenance.LayerSummary
	Summary      layerprovenance.Summary
}

func decode(t *testing.T, content string) records {
	t.Helper()
	var got records
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		var meta struct {
			Type string `json:"type"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &meta))
		switch meta.Type {
		case layerprovenance.RecordTypeHeader:
			require.NoError(t, json.Unmarshal([]byte(line), &got.Header))
		case layerprovenance.RecordTypeFinding:
			var f layerprovenance.Finding
			require.NoError(t, json.Unmarshal([]byte(line), &f))
			got.Findings = append(got.Findings, f)
		case layerprovenance.RecordTypeLayerSummary:
			var ls layerprovenance.LayerSummary
			require.NoError(t, json.Unmarshal([]byte(line), &ls))
			got.LayerSummary = append(got.LayerSummary, ls)
		case layerprovenance.RecordTypeSummary:
			require.NoError(t, json.Unmarshal([]byte(line), &got.Summary))
		}
	}
	return got
}

func TestWriter_Identical(t *testing.T) {
	report := withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0002", "openssl", "1.0.0", baseDiffID),
	))

	// First run, then a second run of the same input diffed against the first.
	previous := loadPrevious(t, write(t, report, nil))
	got := decode(t, write(t, report, previous))

	assert.Equal(t, 2, got.Summary.Findings.Total)
	assert.Equal(t, 0, got.Summary.Findings.Added)
	assert.Equal(t, 0, got.Summary.Findings.Removed)
	assert.Equal(t, 2, got.Summary.Findings.Unchanged)
	for _, f := range got.Findings {
		assert.Equal(t, layerprovenance.StatusUnchanged, f.Status)
	}
	assert.True(t, got.Summary.Reconciled)
}

func TestWriter_Added(t *testing.T) {
	previous := loadPrevious(t, write(t, withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
	)), nil))

	current := withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0002", "openssl", "1.0.0", appDiffID),
	))
	got := decode(t, write(t, current, previous))

	assert.Equal(t, 1, got.Summary.Findings.Added)
	assert.Equal(t, 0, got.Summary.Findings.Removed)
	assert.Equal(t, 1, got.Summary.Findings.Unchanged)
	for _, f := range got.Findings {
		if f.Vulnerability.ID == "CVE-2024-0002" {
			assert.Equal(t, layerprovenance.StatusAdded, f.Status)
			require.NotNil(t, f.Layer)
			assert.Equal(t, ftypes.LayerRoleApplication, f.Layer.Role)
		}
	}
}

func TestWriter_Removed(t *testing.T) {
	previous := loadPrevious(t, write(t, withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0002", "openssl", "1.0.0", baseDiffID),
	)), nil))

	current := withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
	))
	got := decode(t, write(t, current, previous))

	assert.Equal(t, 0, got.Summary.Findings.Added)
	assert.Equal(t, 1, got.Summary.Findings.Removed)
	assert.Equal(t, 1, got.Summary.Findings.Unchanged)

	var removed *layerprovenance.Finding
	for i := range got.Findings {
		if got.Findings[i].Status == layerprovenance.StatusRemoved {
			removed = &got.Findings[i]
		}
	}
	require.NotNil(t, removed)
	assert.Equal(t, "CVE-2024-0002", removed.Vulnerability.ID)
	// A removed finding carries the layer it had in the previous scan.
	require.Len(t, removed.PreviousLayers, 1)
	assert.Equal(t, baseDiffID, removed.PreviousLayers[0].DiffID)
	assert.Equal(t, ftypes.LayerRoleBase, removed.PreviousLayers[0].Role)
	// It is grouped under that layer's role, not left as unknown.
	assert.Equal(t, 1, got.Summary.ByRole["base"].Removed)
	assert.NotContains(t, got.Summary.ByRole, "unknown")
}

// TestWriter_PackageUpgrade checks that an upgrade which removes an old
// vulnerability and introduces a new one is reported as two events, not as a
// single net change.
func TestWriter_PackageUpgrade(t *testing.T) {
	previous := loadPrevious(t, write(t, withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
	)), nil))

	current := withProvenance(testReport(
		vuln("CVE-2024-0002", "openssl", "1.1.0", appDiffID),
	))
	got := decode(t, write(t, current, previous))

	assert.Equal(t, 1, got.Summary.Findings.Added)
	assert.Equal(t, 1, got.Summary.Findings.Removed)
	assert.Equal(t, 0, got.Summary.Findings.Unchanged)
	assert.Equal(t, 2, got.Summary.Findings.Total)

	var added, removed *layerprovenance.Finding
	for i := range got.Findings {
		switch got.Findings[i].Status {
		case layerprovenance.StatusAdded:
			added = &got.Findings[i]
		case layerprovenance.StatusRemoved:
			removed = &got.Findings[i]
		}
	}
	require.NotNil(t, added)
	require.NotNil(t, removed)
	assert.Equal(t, "1.1.0", added.Package.Version)
	assert.Equal(t, appDiffID, added.Layer.DiffID)
	assert.Equal(t, "1.0.0", removed.Package.Version)
	require.Len(t, removed.PreviousLayers, 1)
	assert.Equal(t, baseDiffID, removed.PreviousLayers[0].DiffID)
}

// TestWriter_SameVulnInMultiplePackages checks that a vulnerability affecting
// several packages is located per package and version, not collapsed into one
// record.
func TestWriter_SameVulnInMultiplePackages(t *testing.T) {
	report := withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0001", "libssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0001", "libssl", "2.0.0", appDiffID),
	))
	got := decode(t, write(t, report, nil))

	require.Len(t, got.Findings, 3)
	pkgs := map[string]string{}
	for _, f := range got.Findings {
		pkgs[f.Package.Name+"@"+f.Package.Version] = f.Identity
	}
	// Three distinct identities for the same vulnerability.
	assert.Len(t, pkgs, 3)
	assert.NotEqual(t, pkgs["libssl@1.0.0"], pkgs["libssl@2.0.0"])
}

// TestWriter_LayerSummaryReconciles checks that the per-layer counts agree with
// the finding records: each finding is attributed to exactly one layer.
func TestWriter_LayerSummaryReconciles(t *testing.T) {
	report := withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0002", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0003", "libssl", "1.0.0", appDiffID),
	))
	got := decode(t, write(t, report, nil))

	perLayer := map[string]int{}
	for _, f := range got.Findings {
		require.NotNil(t, f.Layer)
		perLayer[f.Layer.DiffID]++
	}

	summaryTotal := 0
	summaryPerLayer := map[string]int{}
	for _, ls := range got.LayerSummary {
		summaryTotal += ls.Findings.Total
		summaryPerLayer[ls.Layer.DiffID] = ls.Findings.Total
	}
	assert.Equal(t, len(got.Findings), summaryTotal)
	assert.Equal(t, perLayer, summaryPerLayer)
	assert.Equal(t, 2, summaryPerLayer[baseDiffID])
	assert.Equal(t, 1, summaryPerLayer[appDiffID])
}

// TestWriter_Deterministic checks that the same two inputs produce a
// byte-identical report, regardless of the order of the vulnerabilities.
func TestWriter_Deterministic(t *testing.T) {
	a := withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0002", "libssl", "1.0.0", appDiffID),
		vuln("CVE-2024-0003", "musl", "1.0.0", midDiffID),
	))
	b := withProvenance(testReport(
		// Same findings in a different order.
		vuln("CVE-2024-0003", "musl", "1.0.0", midDiffID),
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0002", "libssl", "1.0.0", appDiffID),
	))

	prev := loadPrevious(t, write(t, a, nil))
	first := write(t, a, prev)
	second := write(t, b, prev)
	assert.Equal(t, first, second)
}

// TestWriter_BaseImageChange checks that a change caused by switching the base
// image is attributed to the base layer rather than to the application.
func TestWriter_BaseImageChange(t *testing.T) {
	previous := loadPrevious(t, write(t, withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
	)), nil))

	current := withProvenance(testReport(
		// The application layer is unchanged, but the base image was replaced,
		// so the finding now points at a different base layer.
		vuln("CVE-2024-0001", "openssl", "1.0.0", "sha256:new-base-layer"),
	))
	// The new image has its own base layer and an application layer.
	current.Metadata.Layers = ftypes.Layers{
		{Size: 100, Digest: "sha256:new-base-digest", DiffID: "sha256:new-base-layer"},
		{Size: 300, Digest: "sha256:app-digest", DiffID: appDiffID},
	}
	current.LayerProvenance = &types.LayerProvenance{
		Roles: []ftypes.LayerRole{ftypes.LayerRoleBase, ftypes.LayerRoleApplication},
	}
	got := decode(t, write(t, current, previous))

	require.Len(t, got.Findings, 1)
	f := got.Findings[0]
	assert.Equal(t, layerprovenance.StatusUnchanged, f.Status)
	assert.Equal(t, ftypes.LayerRoleBase, f.Layer.Role)
	assert.True(t, f.LayerChanged)
	// The change is grouped under the base role: it is not counted as a new
	// finding, and not attributed to the application.
	assert.Equal(t, 1, got.Summary.ByRole["base"].Total)
	assert.Equal(t, 0, got.Summary.ByRole["application"].Total)
	assert.Equal(t, 0, got.Summary.Findings.Added)
	assert.Equal(t, 1, got.Summary.Findings.LayerChanged)
}

func TestLoadPrevious_Missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	_, err := layerprovenance.LoadPrevious(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), path)
	assert.Contains(t, err.Error(), "not found")
}

func TestLoadPrevious_Corrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(
		`{"type":"header","schemaVersion":1}`+"\nnot-json\n"), 0o600))

	_, err := layerprovenance.LoadPrevious(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), path)
	assert.Contains(t, err.Error(), "corrupt")
	assert.Contains(t, err.Error(), "line 2")
}

func TestLoadPrevious_Incomplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-header.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(`{"type":"finding","identity":"sha256:x"}`+"\n"), 0o600))

	_, err := layerprovenance.LoadPrevious(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete")
	assert.Contains(t, err.Error(), "header")
}

func TestLoadPrevious_Incompatible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(`{"type":"header","schemaVersion":999}`+"\n"), 0o600))

	_, err := layerprovenance.LoadPrevious(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incompatible")
	assert.Contains(t, err.Error(), "999")
}

// TestWriter_SameLayerMultiplePackages checks that several packages in the
// same layer that are affected by the same vulnerability are listed per
// package, while the layer summary still reconciles with the detail.
func TestWriter_SameLayerMultiplePackages(t *testing.T) {
	report := withProvenance(testReport(
		vuln("CVE-2024-0001", "openssl", "1.0.0", baseDiffID),
		vuln("CVE-2024-0001", "libssl", "1.0.0", baseDiffID),
	))
	got := decode(t, write(t, report, nil))

	// Two records for one vulnerability, located by package.
	require.Len(t, got.Findings, 2)
	assert.NotEqual(t, got.Findings[0].Identity, got.Findings[1].Identity)

	var base layerprovenance.LayerSummary
	for _, ls := range got.LayerSummary {
		if ls.Layer.DiffID == baseDiffID {
			base = ls
		}
	}
	assert.Equal(t, 2, base.Findings.Total)
	assert.True(t, got.Summary.Reconciled)
	assert.Equal(t, 2, got.Summary.Findings.Total)
}
