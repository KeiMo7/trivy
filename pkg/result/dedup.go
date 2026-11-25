package result

import (
	"cmp"
	"fmt"
	"slices"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

// vulnerabilityKey is the de-duplication identity of a detected vulnerability.
// It is the five-tuple VulnerabilityID / PkgID / PkgName / InstalledVersion /
// PkgPath: the same CVE reported both by an OS package and by a language
// package (e.g. apk vs jar) collapses only when every element matches.
func vulnerabilityKey(v types.DetectedVulnerability) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s",
		v.VulnerabilityID, v.PkgID, v.PkgName, v.InstalledVersion, v.PkgPath)
}

// shouldOverwrite decides whether a duplicate vulnerability replaces the one
// already kept. The entry with the lexicographically larger FixedVersion wins,
// so an empty fixed version never overrides a concrete remediation version.
func shouldOverwrite(oldVuln, newVuln types.DetectedVulnerability) bool {
	// The same vulnerability must be picked always.
	return oldVuln.FixedVersion < newVuln.FixedVersion
}

// severityRank maps a severity string to a total order. Unknown and empty
// severities rank lowest, matching dbTypes ordering.
func severityRank(severity string) int {
	switch severity {
	case dbTypes.SeverityLow.String():
		return 1
	case dbTypes.SeverityMedium.String():
		return 2
	case dbTypes.SeverityHigh.String():
		return 3
	case dbTypes.SeverityCritical.String():
		return 4
	default:
		// dbTypes.SeverityUnknown, including the empty string.
		return 0
	}
}

// compareVulnerability defines a total order over de-duplicated vulnerabilities.
// The comparator is antisymmetric and transitive:
//  1. Severity (higher first)
//  2. PkgName
//  3. VulnerabilityID
//  4. PkgPath
//  5. InstalledVersion
//
// Returning 0 means the two vulnerabilities are equivalent under the ordering,
// not identical; sort.SliceStable keeps their original relative order.
func compareVulnerability(a, b types.DetectedVulnerability) int {
	if c := cmp.Compare(severityRank(b.Severity), severityRank(a.Severity)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.PkgName, b.PkgName); c != 0 {
		return c
	}
	if c := cmp.Compare(a.VulnerabilityID, b.VulnerabilityID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.PkgPath, b.PkgPath); c != 0 {
		return c
	}
	return cmp.Compare(a.InstalledVersion, b.InstalledVersion)
}

// DedupVulnerabilities collapses duplicate vulnerabilities of a single target.
// The de-duplication key is the five-tuple returned by vulnerabilityKey; on a
// collision the entry with the larger FixedVersion is retained. The surviving
// entries are then ordered by the total comparator above with a stable sort, so
// the output is independent of Go map iteration and of the concurrency order of
// upstream analysis. An empty result is normalized to nil.
func DedupVulnerabilities(vulns []types.DetectedVulnerability) []types.DetectedVulnerability {
	if len(vulns) == 0 {
		return nil
	}

	uniq := make(map[string]types.DetectedVulnerability, len(vulns))
	// order remembers the first occurrence of every key. Map iteration itself is
	// randomized, so the original relative order of equivalent elements must be
	// captured explicitly for the subsequent stable sort to preserve it.
	order := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		key := vulnerabilityKey(vuln)
		if old, ok := uniq[key]; ok {
			if shouldOverwrite(old, vuln) {
				uniq[key] = vuln
			}
			continue
		}
		uniq[key] = vuln
		order = append(order, key)
	}

	deduped := make([]types.DetectedVulnerability, 0, len(order))
	for _, key := range order {
		deduped = append(deduped, uniq[key])
	}
	slices.SortStableFunc(deduped, compareVulnerability)
	return xslices.ZeroToNil(deduped)
}
