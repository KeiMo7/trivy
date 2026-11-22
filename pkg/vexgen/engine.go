package vexgen

import (
	"fmt"
	"sort"
	"strings"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// Options controls a synthesis run.
type Options struct {
	// Author and DocumentTimestamp identify the output document.
	Author string
	// DocumentTimestamp is rendered as the OpenVEX document timestamp. It is
	// supplied by the caller (or derived from SOURCE_DATE_EPOCH) instead of
	// read from the wall clock, so output is reproducible.
	DocumentTimestamp time.Time

	// Now is only used to validate timestamps that claim to be in the future.
	// Zero disables the check.
	Now time.Time
}

// Result is the successful output of a synthesis run.
type Result struct {
	Document  *openvex.VEX
	Reconcile []ReconcileItem
	// Converged holds every final conclusion after timestamp convergence,
	// keyed by its three-part finding key. It drives the round-trip expected
	// set without re-reading review sheets.
	Converged map[FindingKey]ConvergedConclusion
	// ConvergedCount is the number of distinct keys carrying a final conclusion.
	ConvergedCount int
	// TrustedCount is the number of conclusions the consumer will actually
	// filter (not_affected / fixed). The rest are emitted but not filtered.
	TrustedCount int
}

// ConvergedConclusion is one final statement with the scope and identifiers
// needed to build round-trip expectations.
type ConvergedConclusion struct {
	Scope           Scope
	ProductDigest   string
	ProductPURL     string
	VulnerabilityID string
	ComponentPURL   string
	PkgPath         string
	Status          string
	Justification   string
}

// scanIndex is the lookup structure over scan results.
type scanIndex struct {
	// digest hex -> product
	products map[string]*ScanResult
	// product digest -> component purl (exact) -> versions seen
	componentVersions map[string]map[string]map[string]bool
	// exact finding key -> present
	findings map[FindingKey]bool
	// product digest -> vuln -> set of component purls reporting it
	vulnComponents map[string]map[string]map[string]bool
}

func buildScanIndex(scans []ScanResult) (*scanIndex, Issues) {
	var issues Issues
	idx := &scanIndex{
		products:          map[string]*ScanResult{},
		componentVersions: map[string]map[string]map[string]bool{},
		findings:          map[FindingKey]bool{},
		vulnComponents:    map[string]map[string]map[string]bool{},
	}

	for si := range scans {
		s := &scans[si]
		if len(s.Product.RepoDigests) == 0 {
			issues = append(issues, Issue{
				Code:    "SCAN_PRODUCT_NO_DIGEST",
				Message: fmt.Sprintf("scan result for %q has no repo digest; identity cannot be content-based", s.Product.Name),
			})
			continue
		}
		repo, digest, err := digestFromRepoDigest(s.Product.RepoDigests[0])
		if err != nil {
			issues = append(issues, Issue{Code: "SCAN_BAD_DIGEST", Message: err.Error()})
			continue
		}
		hex := digestHex(digest)
		if _, dup := idx.products[hex]; dup {
			issues = append(issues, Issue{
				Code:    "SCAN_DUPLICATE_PRODUCT",
				Message: fmt.Sprintf("digest %s appears in more than one scan result (%s)", digest, repo),
			})
			continue
		}
		idx.products[hex] = s
		idx.componentVersions[hex] = map[string]map[string]bool{}
		idx.vulnComponents[hex] = map[string]map[string]bool{}

		for fi, f := range s.Findings {
			if f.VulnerabilityID == "" {
				issues = append(issues, Issue{
					Code:    "SCAN_FINDING_NO_VULN",
					Message: fmt.Sprintf("product %s finding #%d has no vulnerability id", digest, fi+1),
				})
				continue
			}
			p, err := packageurl.FromString(f.ComponentPURL)
			if err != nil {
				issues = append(issues, Issue{
					Code:    "SCAN_FINDING_BAD_PURL",
					Message: fmt.Sprintf("product %s finding %s has invalid component purl %q: %v", digest, f.VulnerabilityID, f.ComponentPURL, err),
				})
				continue
			}
			if _, ok := idx.componentVersions[hex][f.ComponentPURL]; !ok {
				idx.componentVersions[hex][f.ComponentPURL] = map[string]bool{}
			}
			idx.componentVersions[hex][f.ComponentPURL][p.Version] = true

			idx.findings[FindingKey{
				Product:         hex,
				VulnerabilityID: f.VulnerabilityID,
				ComponentPURL:   f.ComponentPURL,
				PkgPath:         f.PkgPath,
			}] = true

			if _, ok := idx.vulnComponents[hex][f.VulnerabilityID]; !ok {
				idx.vulnComponents[hex][f.VulnerabilityID] = map[string]bool{}
			}
			idx.vulnComponents[hex][f.VulnerabilityID][f.ComponentPURL] = true
		}
	}
	return idx, issues
}

// Build validates every review row against the scan results, converges
// re-judgements, reconciles unmatched rows and synthesizes the OpenVEX
// document. It is all-or-nothing: on any blocking issue it returns Issues and
// no document, having collected every problem in a single pass.
func Build(scans []ScanResult, reviews []ReviewEntry, opts Options) (*Result, []ReconcileItem, Issues) {
	idx, scanIssues := buildScanIndex(scans)

	var issues Issues
	issues = append(issues, scanIssues...)
	if opts.Author == "" {
		issues = append(issues, Issue{Code: "CONFIG_NO_AUTHOR", Message: "document author is required"})
	}
	if opts.DocumentTimestamp.IsZero() {
		issues = append(issues, Issue{Code: "CONFIG_NO_TIMESTAMP", Message: "document timestamp is required (use SOURCE_DATE_EPOCH for reproducibility)"})
	}

	syn := newSynthesis()
	var reconcile []ReconcileItem

	// First pass: validate vocabulary and reconcile unmatched rows. Valid
	// rows are collected in input order so duplicate/conflict detection can
	// reason about timestamps before convergence.
	var validRows []ReviewEntry
	for i := range reviews {
		r := reviews[i]
		entryIssues, item := validateAndClassify(idx, r)
		if len(entryIssues) > 0 {
			issues = append(issues, entryIssues...)
			continue
		}
		if item != nil {
			// Row does not correspond to anything in the scan result.
			// Reconciliation rows are reported but do not block generation.
			reconcile = append(reconcile, *item)
			continue
		}
		validRows = append(validRows, r)
	}
	issues = append(issues, detectConflicts(validRows)...)
	issues = append(issues, validatePathCoverage(idx, validRows)...)

	sort.Slice(reconcile, func(i, j int) bool {
		a, b := reconcile[i], reconcile[j]
		if a.ProductDigest != b.ProductDigest {
			return a.ProductDigest < b.ProductDigest
		}
		if a.VulnerabilityID != b.VulnerabilityID {
			return a.VulnerabilityID < b.VulnerabilityID
		}
		return a.ComponentPURL < b.ComponentPURL
	})

	if len(issues) > 0 {
		sortIssues(issues)
		return nil, reconcile, issues
	}

	// Second pass: converge re-judgements by timestamp. Conflict detection
	// above guarantees every key now has an unambiguous latest row.
	for i := range validRows {
		merge(syn, idx, validRows[i])
	}

	doc := renderDocument(syn, opts)
	res := &Result{
		Document:       doc,
		Reconcile:      reconcile,
		Converged:      convergedView(syn),
		ConvergedCount: len(syn.component) + len(syn.product),
		TrustedCount:   countTrusted(syn),
	}
	return res, reconcile, nil
}

// convergedView flattens the internal synthesis into an exported,
// deterministic map of final conclusions.
func convergedView(syn *synthesis) map[FindingKey]ConvergedConclusion {
	out := make(map[FindingKey]ConvergedConclusion, len(syn.component)+len(syn.product))
	add := func(m map[FindingKey]*conclusion, scope Scope) {
		for k, c := range m {
			out[k] = ConvergedConclusion{
				Scope:           scope,
				ProductDigest:   k.Product,
				ProductPURL:     c.productPURL,
				VulnerabilityID: k.VulnerabilityID,
				ComponentPURL:   k.ComponentPURL,
				PkgPath:         k.PkgPath,
				Status:          c.entry.Status,
				Justification:   c.entry.Justification,
			}
		}
	}
	add(syn.component, ScopeComponent)
	add(syn.product, ScopeProduct)
	return out
}

// validateAndClassify returns either blocking issues, a reconciliation item
// (row does not match the scan), or neither (row is valid and must be merged).
func validateAndClassify(idx *scanIndex, r ReviewEntry) (Issues, *ReconcileItem) {
	loc := func(code, msg string) Issues {
		return Issues{{Code: code, Message: msg, SourceFile: r.SourceFile, Row: r.Row}}
	}

	// --- structural / vocabulary validation ---
	if r.ProductDigest == "" {
		return loc("REVIEW_NO_DIGEST", "review row has no product digest; rows must anchor to a content fingerprint, not a name"), nil
	}
	hex := digestHex(r.ProductDigest)
	product, ok := idx.products[hex]
	if !ok {
		return nil, &ReconcileItem{
			ProductDigest:   r.ProductDigest,
			VulnerabilityID: r.VulnerabilityID,
			Scope:           r.Scope,
			ComponentPURL:   r.ComponentPURL,
			PkgPath:         r.PkgPath,
			Reason:          ReconcileProductMissing,
			Detail:          "no scanned product carries this digest",
			SourceFile:      r.SourceFile,
			Row:             r.Row,
		}
	}

	if r.VulnerabilityID == "" {
		return loc("REVIEW_NO_VULN", "review row has no vulnerability id"), nil
	}
	if r.Scope != ScopeProduct && r.Scope != ScopeComponent {
		return loc("REVIEW_BAD_SCOPE", fmt.Sprintf("scope %q is invalid; expected %q or %q", r.Scope, ScopeProduct, ScopeComponent)), nil
	}
	status := openvex.Status(r.Status)
	if !status.Valid() {
		return loc("REVIEW_BAD_STATUS", fmt.Sprintf("status %q is not a valid OpenVEX status (%s)", r.Status, strings.Join(openvex.Statuses(), ", "))), nil
	}
	// A justification is mandatory for not_affected and must be from the
	// controlled vocabulary. "No review" must never be written as not_affected.
	if status == openvex.StatusNotAffected {
		if strings.TrimSpace(r.Justification) == "" {
			return loc("REVIEW_JUSTIFICATION_MISSING", fmt.Sprintf("%s marked not_affected without a justification", r.VulnerabilityID)), nil
		}
		if !openvex.Justification(r.Justification).Valid() {
			return loc("REVIEW_JUSTIFICATION_INVALID", fmt.Sprintf("justification %q is not valid (%s)", r.Justification, strings.Join(openvex.Justifications(), ", "))), nil
		}
	} else if r.Justification != "" {
		return loc("REVIEW_JUSTIFICATION_NOT_ALLOWED", fmt.Sprintf("status %s must not carry a justification", r.Status)), nil
	}

	if r.Reviewer == "" {
		return loc("REVIEW_NO_REVIEWER", "review row has no reviewer"), nil
	}
	if _, err := time.Parse(time.RFC3339, r.ReviewedAt); err != nil {
		return loc("REVIEW_BAD_TIME", fmt.Sprintf("reviewed_at %q is not RFC3339: %v", r.ReviewedAt, err)), nil
	}

	// --- component-level matching against the scan result ---
	if r.Scope == ScopeComponent {
		if r.ComponentPURL == "" {
			return loc("REVIEW_COMPONENT_NO_PURL", "component-scope row must name a component PURL"), nil
		}
		if _, err := packageurl.FromString(r.ComponentPURL); err != nil {
			return loc("REVIEW_COMPONENT_BAD_PURL", fmt.Sprintf("component purl %q is invalid: %v", r.ComponentPURL, err)), nil
		}
		versions, componentExists := idx.componentVersions[hex][r.ComponentPURL]
		if !componentExists {
			// Distinguish "component absent" from "version changed" by looking
			// for the same type/namespace/name at another version.
			if reason, detail := classifyComponentDrift(idx, hex, r.ComponentPURL); reason != "" {
				return nil, reconcileItem(r, reason, detail)
			}
			return nil, reconcileItem(r, ReconcileComponentMissing,
				fmt.Sprintf("component %s is not present in the scan result of %s", r.ComponentPURL, product.Product.RepoDigests[0]))
		}
		// Component exists at the reviewed version. The finding must still be
		// present. An empty pkg_path means the conclusion covers the whole
		// component (any path); a non-empty path pins it to that occurrence.
		componentHasVuln := idx.vulnComponents[hex][r.VulnerabilityID][r.ComponentPURL]
		if r.PkgPath == "" {
			if componentHasVuln {
				return nil, nil
			}
		} else {
			key := FindingKey{Product: hex, VulnerabilityID: r.VulnerabilityID, ComponentPURL: r.ComponentPURL, PkgPath: r.PkgPath}
			if idx.findings[key] {
				return nil, nil
			}
			// The path-specific occurrence is gone while the vuln remains on
			// the component at another path.
			if componentHasVuln {
				return nil, reconcileItem(r, ReconcileFindingMissing,
					fmt.Sprintf("vulnerability %s is still reported on %s but not at package path %q", r.VulnerabilityID, r.ComponentPURL, r.PkgPath))
			}
		}
		// Staleness guard: if the reviewed version differs from every scanned
		// version, the old conclusion has expired.
		wantVer, _ := purlVersion(r.ComponentPURL)
		if wantVer != "" && !versions[wantVer] {
			return nil, reconcileItem(r, ReconcileVersionChanged,
				fmt.Sprintf("component %s is now present at versions %s; the reviewed version %s is gone",
					r.ComponentPURL, sortedSet(versions), wantVer))
		}
		return nil, reconcileItem(r, ReconcileFindingMissing,
			fmt.Sprintf("vulnerability %s is no longer reported on component %s", r.VulnerabilityID, r.ComponentPURL))
	}

	// Product-scope: the vulnerability must be reported somewhere in this
	// product, otherwise the conclusion has nothing to attach to.
	if _, ok := idx.vulnComponents[hex][r.VulnerabilityID]; !ok {
		return nil, reconcileItem(r, ReconcileFindingMissing,
			fmt.Sprintf("vulnerability %s is not reported anywhere in product %s", r.VulnerabilityID, product.Product.RepoDigests[0]))
	}
	return nil, nil
}

// classifyComponentDrift checks whether a non-matching component PURL is
// explained by the same component (type/namespace/name) existing at a
// different version, in which case the conclusion has expired.
func classifyComponentDrift(idx *scanIndex, hex, reviewedPURL string) (ReconcileReason, string) {
	want, err := packageurl.FromString(reviewedPURL)
	if err != nil || want.Version == "" {
		return "", ""
	}
	for scannedPURL, versions := range idx.componentVersions[hex] {
		got, err := packageurl.FromString(scannedPURL)
		if err != nil {
			continue
		}
		if got.Type == want.Type && got.Namespace == want.Namespace && got.Name == want.Name {
			return ReconcileVersionChanged, fmt.Sprintf(
				"component %s/%s/%s changed from version %s to %s",
				want.Type, want.Namespace, want.Name, want.Version, sortedSet(versions))
		}
	}
	return "", ""
}

func reconcileItem(r ReviewEntry, reason ReconcileReason, detail string) *ReconcileItem {
	return &ReconcileItem{
		ProductDigest:   r.ProductDigest,
		VulnerabilityID: r.VulnerabilityID,
		Scope:           r.Scope,
		ComponentPURL:   r.ComponentPURL,
		PkgPath:         r.PkgPath,
		Reason:          reason,
		Detail:          detail,
		SourceFile:      r.SourceFile,
		Row:             r.Row,
	}
}

// merge converges one validated row. Later ReviewedAt wins; a tie keeps the
// existing entry but is flagged as an error by the caller's duplicate check
// during validation-free convergence here.
func merge(syn *synthesis, idx *scanIndex, r ReviewEntry) {
	hex := digestHex(r.ProductDigest)
	// Product PURL is guaranteed to build here because the scan index already
	// validated the product.
	pp, _ := productPURL(idx.products[hex].Product)

	key := FindingKey{
		Product:         hex,
		VulnerabilityID: r.VulnerabilityID,
		ComponentPURL:   r.ComponentPURL,
		PkgPath:         r.PkgPath,
	}
	c := &conclusion{entry: r, productPURL: pp}

	target := syn.component
	if r.Scope == ScopeProduct {
		target = syn.product
	}
	existing, ok := target[key]
	if !ok {
		target[key] = c
		return
	}
	// Re-judgement: latest timestamp wins. Equal timestamps are ambiguous and
	// treated as a blocking conflict below.
	oldT, _ := time.Parse(time.RFC3339, existing.entry.ReviewedAt)
	newT, _ := time.Parse(time.RFC3339, r.ReviewedAt)
	if newT.After(oldT) {
		target[key] = c
	} else if newT.Equal(oldT) {
		// Mark deterministically; the duplicate-conflict pass rejects this.
		target[key] = c
	}
}

func countTrusted(syn *synthesis) int {
	n := 0
	for _, c := range append(mapsValues(syn.component), mapsValues(syn.product)...) {
		s := openvex.Status(c.entry.Status)
		if s == openvex.StatusNotAffected || s == openvex.StatusFixed {
			n++
		}
	}
	return n
}

func mapsValues[K comparable, V any](m map[K]V) []V {
	out := make([]V, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func sortedSet(s map[string]bool) string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func sortIssues(issues Issues) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].SourceFile != issues[j].SourceFile {
			return issues[i].SourceFile < issues[j].SourceFile
		}
		return issues[i].Row < issues[j].Row
	})
}
