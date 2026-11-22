package vexgen_test

import (
	"context"
	"testing"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/vexgen"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func baseScans() []vexgen.ScanResult {
	return []vexgen.ScanResult{
		{
			Product: vexgen.Product{
				ArtifactType: "container_image",
				Name:         "registry.example.com/app@" + digestA,
				RepoDigests:  []string{"registry.example.com/app@" + digestA},
				RepoTags:     []string{"registry.example.com/app:v1", "registry.example.com/app:latest"},
				Architecture: "amd64",
			},
			Findings: []vexgen.ScanFinding{
				{VulnerabilityID: "CVE-2024-0001", ComponentPURL: "pkg:deb/debian/bash@5.1", ComponentName: "bash", InstalledVersion: "5.1"},
				{VulnerabilityID: "CVE-2024-0001", ComponentPURL: "pkg:deb/debian/curl@7.7", ComponentName: "curl", InstalledVersion: "7.7"},
				{VulnerabilityID: "CVE-2024-0002", ComponentPURL: "pkg:deb/debian/zlib@1.2", ComponentName: "zlib", InstalledVersion: "1.2"},
			},
		},
		{
			Product: vexgen.Product{
				ArtifactType: "container_image",
				Name:         "registry.example.com/worker@" + digestB,
				RepoDigests:  []string{"registry.example.com/worker@" + digestB},
				Architecture: "arm64",
			},
			Findings: []vexgen.ScanFinding{
				{VulnerabilityID: "CVE-2024-1001", ComponentPURL: "pkg:golang/golang.org/x/net@v0.5.0", ComponentName: "x/net", InstalledVersion: "v0.5.0"},
			},
		},
	}
}

func fixedOpts() vexgen.Options {
	return vexgen.Options{
		Author:            "tester",
		DocumentTimestamp: time.Unix(1763942400, 0).UTC(),
	}
}

// TestSameVulnDifferentComponents asserts one vulnerability can carry
// different conclusions on different components, and each survives the
// round-trip with its own status.
func TestSameVulnDifferentComponents(t *testing.T) {
	scans := baseScans()
	reviews := []vexgen.ReviewEntry{
		{ProductDigest: digestA, VulnerabilityID: "CVE-2024-0001", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:deb/debian/bash@5.1", Status: "not_affected",
			Justification: "vulnerable_code_not_in_execute_path", Reviewer: "a", ReviewedAt: "2026-11-10T08:00:00Z"},
		{ProductDigest: digestA, VulnerabilityID: "CVE-2024-0001", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:deb/debian/curl@7.7", Status: "fixed",
			Reviewer: "a", ReviewedAt: "2026-11-10T08:01:00Z"},
		{ProductDigest: digestA, VulnerabilityID: "CVE-2024-0002", Scope: vexgen.ScopeProduct,
			Status: "not_affected", Justification: "vulnerable_code_not_present",
			Reviewer: "a", ReviewedAt: "2026-11-10T08:02:00Z"},
	}
	res, reconcile, issues := vexgen.Build(scans, reviews, fixedOpts())
	require.Nil(t, issues, "expected no blocking issues: %v", issues)
	assert.Empty(t, reconcile)

	// The two component conclusions keep distinct statuses.
	var bashStatus, curlStatus string
	for _, s := range res.Document.Statements {
		for _, p := range s.Products {
			for _, sc := range p.Subcomponents {
				switch sc.ID {
				case "pkg:deb/debian/bash@5.1":
					bashStatus = string(s.Status)
				case "pkg:deb/debian/curl@7.7":
					curlStatus = string(s.Status)
				}
			}
		}
	}
	assert.Equal(t, "not_affected", bashStatus)
	assert.Equal(t, "fixed", curlStatus)

	report, err := vexgen.RoundTrip(context.Background(), scans, res.Document, res.Converged, filepathTemp(t))
	require.NoError(t, err)
	assert.True(t, report.OK(), "round-trip mismatch: %+v", report)
}

// TestRejudgementConverges asserts later timestamps win and exactly one final
// statement exists for the re-judged key.
func TestRejudgementConverges(t *testing.T) {
	scans := baseScans()
	reviews := []vexgen.ReviewEntry{
		{ProductDigest: digestB, VulnerabilityID: "CVE-2024-1001", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:golang/golang.org/x/net@v0.5.0", Status: "affected",
			Reviewer: "a", ReviewedAt: "2026-11-10T08:00:00Z"},
		{ProductDigest: digestB, VulnerabilityID: "CVE-2024-1001", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:golang/golang.org/x/net@v0.5.0", Status: "not_affected",
			Justification: "vulnerable_code_not_present", Reviewer: "b", ReviewedAt: "2026-11-12T08:00:00Z"},
	}
	res, _, issues := vexgen.Build(scans, reviews, fixedOpts())
	require.Nil(t, issues)

	count := 0
	final := ""
	for _, s := range res.Document.Statements {
		if s.Vulnerability.Name == "CVE-2024-1001" {
			count++
			final = string(s.Status)
		}
	}
	assert.Equal(t, 1, count, "re-judgement must converge to a single statement")
	assert.Equal(t, string(openvex.StatusNotAffected), final)
}

// TestConflictingSameTimestamp asserts equal-timestamp contradictory rows block.
func TestConflictingSameTimestamp(t *testing.T) {
	scans := baseScans()
	reviews := []vexgen.ReviewEntry{
		{ProductDigest: digestB, VulnerabilityID: "CVE-2024-1001", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:golang/golang.org/x/net@v0.5.0", Status: "affected",
			Reviewer: "a", ReviewedAt: "2026-11-10T08:00:00Z", SourceFile: "s1.json", Row: 2},
		{ProductDigest: digestB, VulnerabilityID: "CVE-2024-1001", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:golang/golang.org/x/net@v0.5.0", Status: "fixed",
			Reviewer: "b", ReviewedAt: "2026-11-10T08:00:00Z", SourceFile: "s2.json", Row: 2},
	}
	_, _, issues := vexgen.Build(scans, reviews, fixedOpts())
	require.NotNil(t, issues)
	found := false
	for _, e := range issues {
		if e.Code == "REVIEW_CONFLICT" {
			found = true
		}
	}
	assert.True(t, found)
}

// TestFailureInvalidJustification asserts a not_affected row without a valid
// justification blocks generation and points at the offending row.
func TestFailureInvalidJustification(t *testing.T) {
	scans := baseScans()
	reviews := []vexgen.ReviewEntry{
		{ProductDigest: digestA, VulnerabilityID: "CVE-2024-0002", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:deb/debian/zlib@1.2", Status: "not_affected",
			Reviewer: "a", ReviewedAt: "2026-11-10T08:00:00Z", SourceFile: "sheet.json", Row: 7},
	}
	_, _, issues := vexgen.Build(scans, reviews, fixedOpts())
	require.NotNil(t, issues)
	codes := map[string]bool{}
	for _, e := range issues {
		codes[e.Code] = true
		assert.Equal(t, "sheet.json", e.SourceFile)
		assert.Equal(t, 7, e.Row)
	}
	assert.True(t, codes["REVIEW_JUSTIFICATION_MISSING"])
}

// TestFailureEntryMissing reconciles a row whose component is absent, and a
// row whose component version drifted, without blocking the whole document.
func TestFailureEntryMissingAndVersionDrift(t *testing.T) {
	scans := baseScans()
	reviews := []vexgen.ReviewEntry{
		// Component does not exist at all.
		{ProductDigest: digestA, VulnerabilityID: "CVE-2024-0009", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:deb/debian/ghost@9.9", Status: "not_affected",
			Justification: "component_not_present", Reviewer: "a", ReviewedAt: "2026-11-10T08:00:00Z", SourceFile: "s.json", Row: 2},
		// Same component identity but older version -> stale conclusion.
		{ProductDigest: digestB, VulnerabilityID: "CVE-2024-1001", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:golang/golang.org/x/net@v0.4.0", Status: "not_affected",
			Justification: "vulnerable_code_not_present", Reviewer: "a", ReviewedAt: "2026-11-10T08:01:00Z", SourceFile: "s.json", Row: 3},
		// One valid row so generation still proceeds.
		{ProductDigest: digestA, VulnerabilityID: "CVE-2024-0002", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:deb/debian/zlib@1.2", Status: "fixed",
			Reviewer: "a", ReviewedAt: "2026-11-10T08:02:00Z", SourceFile: "s.json", Row: 4},
	}
	res, reconcile, issues := vexgen.Build(scans, reviews, fixedOpts())
	require.Nil(t, issues)
	reasons := map[vexgen.ReconcileReason]int{}
	for _, r := range reconcile {
		reasons[r.Reason]++
	}
	assert.Equal(t, 1, reasons[vexgen.ReconcileComponentMissing])
	assert.Equal(t, 1, reasons[vexgen.ReconcileVersionChanged])
	// The stale/absent rows must not produce statements.
	for _, s := range res.Document.Statements {
		assert.NotEqual(t, "CVE-2024-0009", string(s.Vulnerability.Name))
	}
}

// TestZeroHitsIsFailure asserts a document that matches nothing on round-trip
// is an explicit error rather than a silent "nothing to filter".
func TestZeroHitsIsFailure(t *testing.T) {
	scans := baseScans()
	// Build a valid document for a vulnerability the scan does not contain.
	doc := &openvex.VEX{
		Context:   openvex.ContextLocator(),
		Author:    "tester",
		Timestamp: ptr(time.Unix(1763942400, 0).UTC()),
		Version:   1,
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-9999-0000"},
				Products: []openvex.Product{
					{Component: openvex.Component{ID: "pkg:oci/app"}},
				},
				Status:        openvex.StatusNotAffected,
				Justification: openvex.ComponentNotPresent,
			},
		},
	}
	converged := map[vexgen.FindingKey]vexgen.ConvergedConclusion{
		{Product: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VulnerabilityID: "CVE-9999-0000"}: {
			Scope: vexgen.ScopeProduct, ProductDigest: digestA, VulnerabilityID: "CVE-9999-0000",
			Status: "not_affected",
		},
	}
	_, err := vexgen.RoundTrip(context.Background(), scans, doc, converged, filepathTemp(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zero hits")
}

// TestRetagDoesNotChangeIdentity asserts the same digest under different tags
// produces the same product PURL and the conclusion still matches.
func TestRetagDoesNotChangeIdentity(t *testing.T) {
	scansA := baseScans()
	scansB := baseScans()
	// Change only the tags; digest and findings are identical.
	scansB[0].Product.RepoTags = []string{"registry.example.com/app:completely-different-tag"}

	reviews := []vexgen.ReviewEntry{
		{ProductDigest: digestA, VulnerabilityID: "CVE-2024-0002", Scope: vexgen.ScopeComponent,
			ComponentPURL: "pkg:deb/debian/zlib@1.2", Status: "fixed",
			Reviewer: "a", ReviewedAt: "2026-11-10T08:00:00Z"},
	}
	res1, _, issues := vexgen.Build(scansA, reviews, fixedOpts())
	require.Nil(t, issues)
	res2, _, issues := vexgen.Build(scansB, reviews, fixedOpts())
	require.Nil(t, issues)
	assert.Equal(t, res1.Document.Statements[0].Products[0].ID, res2.Document.Statements[0].Products[0].ID)
}
