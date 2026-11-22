// Package vexgen synthesizes a machine-readable OpenVEX document from review
// conclusions (复核结论) and Trivy scan results, without changing any
// consumer-side interpretation rules.
//
// The generated document is consumed by the existing, unmodified VEX pipeline
// (pkg/vex), so every identifier written here must already be present in the
// scan result: product identity comes from the OCI content digest (never the
// tag), and component identity comes from the component PURL recorded by the
// scanner.
package vexgen

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Input model ---------------------------------------------------------------

// ScanResult is the scanner-side input. It is the subset of types.Report that
// carries the identifiers the generator is allowed to use.
type ScanResult struct {
	// Product identifies the scanned artifact. Identity is content-based:
	// for container images the repo digest (sha256) is the anchor, and tags
	// are carried only as informational metadata.
	Product Product `json:"product"`

	// Findings are the vulnerabilities the scanner actually reported, each
	// anchored to a component via its PURL. Multiple findings may share the
	// same vulnerability ID on different components or package paths.
	Findings []ScanFinding `json:"findings"`
}

// Product is the scanned artifact. At least one RepoDigest is required for
// container images; the digest is what makes re-tagging irrelevant.
type Product struct {
	// ArtifactType is "container_image" in the supported flow.
	ArtifactType string `json:"artifact_type"`

	// Name is informational only and must never be used for matching.
	Name string `json:"name"`

	// RepoDigests are content fingerprints, e.g.
	// "example.com/app@sha256:abcd...". The first entry anchors identity.
	RepoDigests []string `json:"repo_digests"`

	// RepoTags are labels and are deliberately excluded from identity.
	RepoTags []string `json:"repo_tags,omitempty"`

	// Architecture feeds the OCI PURL qualifier, matching Trivy's own
	// purl.parseOCI output.
	Architecture string `json:"architecture,omitempty"`
}

// ScanFinding is one scanner finding: a vulnerability on one component.
type ScanFinding struct {
	VulnerabilityID string `json:"vulnerability_id"`

	// ComponentPURL is the exact PURL the scanner attached to the component.
	ComponentPURL string `json:"component_purl"`

	// ComponentName and InstalledVersion are informational; validation uses
	// the PURL as the source of truth.
	ComponentName    string `json:"component_name,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`

	// PkgPath disambiguates the same component appearing at multiple paths
	// inside one product (requirement: partial review must not erase the rest).
	PkgPath string `json:"pkg_path,omitempty"`
}

// FindingKey is the three-part key (product + vulnerability + affected
// component) that defines the granularity of a review conclusion. PkgPath is
// included so the same component at different paths stays distinct.
type FindingKey struct {
	Product         string
	VulnerabilityID string
	ComponentPURL   string
	PkgPath         string
}

func (k FindingKey) String() string {
	if k.PkgPath == "" {
		return fmt.Sprintf("%s | %s | %s", k.Product, k.VulnerabilityID, k.ComponentPURL)
	}
	return fmt.Sprintf("%s | %s | %s | %s", k.Product, k.VulnerabilityID, k.ComponentPURL, k.PkgPath)
}

// Scope distinguishes product-level conclusions (e.g. this product does not
// carry the affected business function) from component-level conclusions.
type Scope string

const (
	// ScopeProduct applies to the whole product regardless of component.
	ScopeProduct Scope = "product"
	// ScopeComponent applies only to the named component within the product.
	ScopeComponent Scope = "component"
)

// ReviewEntry is one row in a review sheet. Sheets from multiple reviewers and
// multiple review rounds are concatenated; ordering across files is resolved
// by ReviewedAt, never by sheet order.
type ReviewEntry struct {
	// ProductDigest anchors the row to a product by content fingerprint,
	// never by name. It must match a ScanResult.Product digest.
	ProductDigest string `json:"product_digest"`

	VulnerabilityID string `json:"vulnerability_id"`

	// Scope is product|component.
	Scope Scope `json:"scope"`

	// ComponentPURL is required for component scope and ignored for product
	// scope.
	ComponentPURL string `json:"component_purl,omitempty"`

	// PkgPath optionally narrows a component row to one package path.
	PkgPath string `json:"pkg_path,omitempty"`

	// Status is an OpenVEX status vocabulary value.
	Status string `json:"status"`

	// Justification is required (and valid) for not_affected.
	Justification string `json:"justification,omitempty"`

	// Reviewer records who made the call, for the audit trail.
	Reviewer string `json:"reviewer"`

	// ReviewedAt is an RFC3339 timestamp used to converge re-judgements.
	ReviewedAt string `json:"reviewed_at"`

	// SourceFile is the originating sheet, filled in by the loader for error
	// reporting; not part of the sheet schema itself.
	SourceFile string `json:"source_file,omitempty"`

	// Row is the 1-based row number in the originating sheet.
	Row int `json:"row,omitempty"`
}

// ReconcileReason explains why a review row has no matching scan finding.
type ReconcileReason string

const (
	// ReconcileComponentMissing means no component with that PURL exists in
	// the current scan result.
	ReconcileComponentMissing ReconcileReason = "component_not_found"
	// ReconcileVersionChanged means the component exists but at a different
	// version, so the old conclusion is stale.
	ReconcileVersionChanged ReconcileReason = "version_changed"
	// ReconcileFindingMissing means the component exists but the
	// vulnerability is no longer reported on it.
	ReconcileFindingMissing ReconcileReason = "finding_not_found"
	// ReconcileProductMissing means no scanned product carries the digest.
	ReconcileProductMissing ReconcileReason = "product_not_found"
)

// ReconcileItem is one row of the separate reconciliation report.
type ReconcileItem struct {
	ProductDigest   string          `json:"product_digest"`
	VulnerabilityID string          `json:"vulnerability_id"`
	Scope           Scope           `json:"scope"`
	ComponentPURL   string          `json:"component_purl,omitempty"`
	PkgPath         string          `json:"pkg_path,omitempty"`
	Reason          ReconcileReason `json:"reason"`
	Detail          string          `json:"detail"`
	SourceFile      string          `json:"source_file"`
	Row             int             `json:"row"`
}

// Issue is a generation-blocking validation problem. Any issue aborts the
// whole document; all issues are collected in one pass and returned together.
type Issue struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	SourceFile string `json:"source_file,omitempty"`
	Row        int    `json:"row,omitempty"`
}

func (e Issue) Error() string {
	loc := e.Code
	if e.SourceFile != "" {
		loc = fmt.Sprintf("%s (%s:%d)", e.Code, e.SourceFile, e.Row)
	}
	return loc + ": " + e.Message
}

// Issues is the full, ordered set of blocking problems.
type Issues []Issue

func (e Issues) Error() string {
	parts := make([]string, 0, len(e))
	for _, i := range e {
		parts = append(parts, i.Error())
	}
	return fmt.Sprintf("%d issue(s) block VEX generation:\n  - %s", len(e), strings.Join(parts, "\n  - "))
}

// Converged conclusion ------------------------------------------------------

type conclusion struct {
	entry       ReviewEntry
	productPURL string // OCI PURL of the product, derived from the scan result
}

// synthesis is the internal working state after validation and convergence.
type synthesis struct {
	docTimestamp time.Time
	author       string
	// conclusions keyed by FindingKey for component scope, and by
	// product+vuln for product scope.
	component map[FindingKey]*conclusion
	product   map[FindingKey]*conclusion
}

func newSynthesis() *synthesis {
	return &synthesis{
		component: map[FindingKey]*conclusion{},
		product:   map[FindingKey]*conclusion{},
	}
}

// sortedKeys returns map keys in deterministic order for reproducible output.
func sortedKeys[V any](m map[FindingKey]V) []FindingKey {
	keys := make([]FindingKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Product != b.Product {
			return a.Product < b.Product
		}
		if a.VulnerabilityID != b.VulnerabilityID {
			return a.VulnerabilityID < b.VulnerabilityID
		}
		if a.ComponentPURL != b.ComponentPURL {
			return a.ComponentPURL < b.ComponentPURL
		}
		return a.PkgPath < b.PkgPath
	})
	return keys
}
