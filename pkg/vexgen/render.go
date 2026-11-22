package vexgen

import (
	"fmt"
	"sort"
	"strings"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"
)

// detectConflicts enforces a total order on re-judgements. Two rows on the
// same key must not carry the same timestamp with different outcomes: such a
// pair has no "latest" winner and is rejected instead of guessed at.
func detectConflicts(rows []ReviewEntry) Issues {
	type slot struct {
		row ReviewEntry
	}
	keys := map[FindingKey][]slot{}
	for _, r := range rows {
		k := FindingKey{
			Product:         digestHex(r.ProductDigest),
			VulnerabilityID: r.VulnerabilityID,
			ComponentPURL:   r.ComponentPURL,
			PkgPath:         r.PkgPath,
		}
		keys[k] = append(keys[k], slot{r})
	}

	var issues Issues
	for k, slots := range keys {
		// Group by timestamp; within one timestamp the outcome must be unique.
		byTime := map[string][]ReviewEntry{}
		for _, s := range slots {
			byTime[s.row.ReviewedAt] = append(byTime[s.row.ReviewedAt], s.row)
		}
		for ts, group := range byTime {
			if len(group) < 2 {
				continue
			}
			first := group[0]
			for _, g := range group[1:] {
				if g.Status != first.Status || g.Justification != first.Justification || g.Scope != first.Scope {
					issues = append(issues, Issue{
						Code: "REVIEW_CONFLICT",
						Message: fmt.Sprintf(
							"conflicting re-judgements at the same timestamp %s for %s: %s/%s vs %s/%s; no unambiguous winner",
							ts, k, first.Status, first.Justification, g.Status, g.Justification),
						SourceFile: g.SourceFile,
						Row:        g.Row,
					})
				}
			}
		}
	}
	return issues
}

// renderDocument turns converged conclusions into an OpenVEX document.
//
// Statement shapes are chosen to match the consumer's existing matching code
// (pkg/vex/openvex.go + go-vex Matches), which is the hard constraint that
// keeps round-trip hits non-zero:
//
//   - Component scope -> one statement per (product OCI PURL, component PURL,
//     vulnerability). The product carries the component as a subcomponent.
//   - Product scope   -> one statement per (product OCI PURL, vulnerability)
//     with no subcomponent, so it matches every component under that product
//     during the leaf-to-root traversal.
func renderDocument(syn *synthesis, opts Options) *openvex.VEX {
	doc := &openvex.VEX{
		Context:    openvex.ContextLocator(),
		Author:     opts.Author,
		AuthorRole: "VEX generation pipeline",
		Timestamp:  ptrTime(opts.DocumentTimestamp.UTC()),
		Version:    1,
	}

	// Component conclusions are grouped by (product, vuln, component PURL),
	// dropping pkg_path: the consumer matches a subcomponent by PURL only, so
	// several same-PURL path findings collapse into one statement. The path
	// coverage validator guarantees every such group has a single outcome.
	type stmtKey struct {
		product, vuln, purl string
	}
	groups := map[stmtKey]*conclusion{}
	var groupOrder []stmtKey
	for _, k := range sortedKeys(syn.component) {
		gk := stmtKey{k.Product, k.VulnerabilityID, k.ComponentPURL}
		if _, ok := groups[gk]; !ok {
			groupOrder = append(groupOrder, gk)
		}
		groups[gk] = syn.component[k]
	}
	for _, gk := range groupOrder {
		c := groups[gk]
		doc.Statements = append(doc.Statements, openvex.Statement{
			Vulnerability: openvex.Vulnerability{Name: openvex.VulnerabilityID(gk.vuln)},
			Products: []openvex.Product{
				{
					Component: openvex.Component{ID: c.productPURL},
					Subcomponents: []openvex.Subcomponent{
						{Component: openvex.Component{ID: gk.purl}},
					},
				},
			},
			Status:        openvex.Status(c.entry.Status),
			Justification: openvex.Justification(c.entry.Justification),
		})
	}

	for _, k := range sortedKeys(syn.product) {
		c := syn.product[k]
		doc.Statements = append(doc.Statements, openvex.Statement{
			Vulnerability: openvex.Vulnerability{Name: openvex.VulnerabilityID(k.VulnerabilityID)},
			Products: []openvex.Product{
				{Component: openvex.Component{ID: c.productPURL}},
			},
			Status:        openvex.Status(c.entry.Status),
			Justification: openvex.Justification(c.entry.Justification),
		})
	}

	return doc
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

// validatePathCoverage enforces the consumer's real matching granularity.
// go-vex matches a subcomponent by PURL only; package paths are not part of
// PURL matching. Therefore one component-level statement necessarily applies
// to every scan finding with that PURL, regardless of pkg_path.
//
// Two failure modes are rejected instead of being silently collapsed:
//  1. the same PURL has several paths but review covers only some -> the
//     un-reviewed paths would otherwise inherit a conclusion they never got;
//  2. reviewed paths carry different final outcomes -> no single statement can
//     represent them, and "no review" must never be rendered as "not_affected".
//
// A product-scope conclusion on the same vulnerability covers the whole
// product and therefore satisfies coverage for all its paths.
func validatePathCoverage(idx *scanIndex, rows []ReviewEntry) Issues {
	// Collect the set of (product, vuln, componentPURL) that have multiple
	// pkg_path occurrences in the scan.
	type pvk struct {
		hex, vuln, purl string
	}
	multiPath := map[pvk][]string{}
	for hex, vulns := range idx.vulnComponents {
		for vuln, purls := range vulns {
			for p := range purls {
				paths := pathSet(idx, hex, vuln, p)
				if len(paths) > 1 {
					multiPath[pvk{hex, vuln, p}] = paths
				}
			}
		}
	}
	if len(multiPath) == 0 {
		return nil
	}

	// Final outcome per key after timestamp convergence. A row with an empty
	// pkg_path is a wildcard: it covers every occurrence of that component.
	type outcome struct {
		status, justification string
		at                    string
	}
	componentOutcome := map[pvk]map[string]outcome{} // key -> pkg_path -> outcome
	productCovered := map[pvk]bool{}
	for _, r := range rows {
		hex := digestHex(r.ProductDigest)
		k := pvk{hex, r.VulnerabilityID, r.ComponentPURL}
		if r.Scope == ScopeProduct {
			// A product conclusion covers all component paths for this vuln.
			for mk := range multiPath {
				if mk.hex == hex && mk.vuln == r.VulnerabilityID {
					productCovered[mk] = true
				}
			}
			continue
		}
		if _, ok := multiPath[k]; !ok {
			continue
		}
		if componentOutcome[k] == nil {
			componentOutcome[k] = map[string]outcome{}
		}
		// Keep the newest row per path; equal timestamps are rejected elsewhere.
		if cur, ok := componentOutcome[k][r.PkgPath]; !ok || r.ReviewedAt > cur.at {
			componentOutcome[k][r.PkgPath] = outcome{r.Status, r.Justification, r.ReviewedAt}
		}
	}

	var issues Issues
	for k, paths := range multiPath {
		if productCovered[k] {
			continue
		}
		got := componentOutcome[k]
		// A wildcard (empty-path) conclusion covers every occurrence.
		wildcard, hasWildcard := got[""]
		// Coverage: every scanned path must be covered, either explicitly or by
		// a wildcard conclusion.
		var missing []string
		for _, p := range paths {
			if _, ok := got[p]; !ok && !hasWildcard {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			issues = append(issues, Issue{
				Code: "REVIEW_PATH_PARTIAL",
				Message: fmt.Sprintf(
					"%s on %s appears at %d package paths but only some were reviewed; unreviewed paths %s would inherit an un-reviewed conclusion, so generation is blocked",
					k.vuln, k.purl, len(paths), strings.Join(missing, ", ")),
			})
			continue
		}
		// Uniformity: all path outcomes (wildcard included) must be identical
		// because one PURL statement cannot distinguish them on the consumer.
		reference := wildcard
		if !hasWildcard {
			reference = got[paths[0]]
		}
		for _, p := range paths {
			o, ok := got[p]
			if !ok {
				o = wildcard // covered by the wildcard row
			}
			if ok && (o.status != reference.status || o.justification != reference.justification) {
				issues = append(issues, Issue{
					Code: "REVIEW_PATH_DIVERGENT",
					Message: fmt.Sprintf(
						"%s on %s has different conclusions across package paths (reference=%s/%s vs %s=%s/%s); the consumer matches by PURL only, so express this as a product-scope conclusion or make the component conclusions identical",
						k.vuln, k.purl, reference.status, reference.justification, p, o.status, o.justification),
				})
				break
			}
		}
	}
	return issues
}

// pathSet returns the distinct pkg_path values for one finding key. An empty
// path is normalised to "" so callers can compare it directly.
func pathSet(idx *scanIndex, hex, vuln, componentPURL string) []string {
	seen := map[string]bool{}
	for key := range idx.findings {
		if key.Product == hex && key.VulnerabilityID == vuln && key.ComponentPURL == componentPURL {
			seen[key.PkgPath] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
