package vexgen

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

// ExpectedHit is one conclusion the consumer is expected to act on.
type ExpectedHit struct {
	ProductDigest   string
	VulnerabilityID string
	ComponentPURL   string
	PkgPath         string
	// ExpectedStatus is the consumer-side FindingStatus the round-trip must
	// produce ("not_affected" or "fixed").
	ExpectedStatus string
}

// HitObservation is what the consumer actually did with one finding.
type HitObservation struct {
	ProductDigest   string
	VulnerabilityID string
	ComponentPURL   string
	PkgPath         string
	Status          string
	Source          string
}

// RoundTripReport compares the conclusions the generated document promises
// against what the unmodified Trivy VEX consumer does when the document is fed
// back. A zero-hit run is an explicit failure, never "nothing to filter".
type RoundTripReport struct {
	ExpectedCount  int              `json:"expected_count"`
	ObservedCount  int              `json:"observed_count"`
	MissingHits    []string         `json:"missing_hits"`
	UnexpectedHits []string         `json:"unexpected_hits"`
	StatusMismatch []string         `json:"status_mismatch"`
	Observations   []HitObservation `json:"observations"`
}

// OK is true only when the observed hit set equals the expected set exactly
// (one-for-one, no more and no fewer) and every status matches.
func (r *RoundTripReport) OK() bool {
	return len(r.MissingHits) == 0 && len(r.UnexpectedHits) == 0 && len(r.StatusMismatch) == 0
}

// expectedHits extracts the consumer-trustable conclusions (not_affected /
// fixed). Other statuses are valid OpenVEX but the existing consumer does not
// filter on them, so they must not appear in the expected hit set.
func expectedHits(converged map[FindingKey]ConvergedConclusion) []ExpectedHit {
	var out []ExpectedHit
	for _, k := range sortedKeys(converged) {
		c := converged[k]
		if c.Status != "not_affected" && c.Status != "fixed" {
			continue
		}
		out = append(out, ExpectedHit{
			ProductDigest:   c.ProductDigest,
			VulnerabilityID: c.VulnerabilityID,
			ComponentPURL:   c.ComponentPURL,
			PkgPath:         c.PkgPath,
			ExpectedStatus:  c.Status,
		})
	}
	return out
}

// RoundTrip rehydrates Trivy reports from the scan results, runs the real
// consumer (vex.Filter) on the generated document, and asserts an exact
// expected-vs-observed match set with per-finding status comparison.
func RoundTrip(ctx context.Context, scans []ScanResult, doc *openvex.VEX, converged map[FindingKey]ConvergedConclusion, docSource string) (*RoundTripReport, error) {
	expected := expectedHits(converged)
	if len(expected) == 0 {
		return nil, xerrors.New("round-trip failure: no trustable conclusions (not_affected/fixed) to verify; zero-hit would be indistinguishable from a broken match")
	}

	// Indented marshalling keeps the delivered document human-readable and
	// byte-identical to what the `generate` subcommand writes.
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, xerrors.Errorf("marshal generated document: %w", err)
	}
	raw = append(raw, '\n')

	// Write through a temp file path supplied by the caller environment is
	// avoided: vex.NewDocument needs a path, so the caller provides one.
	if docSource == "" {
		return nil, xerrors.New("round-trip requires a document file path for the file-based VEX source")
	}
	if err := writeFileReadOnly(docSource, raw); err != nil {
		return nil, err
	}

	expectedByKey := map[FindingKey]ExpectedHit{}
	for _, e := range expected {
		// A conclusion with no pkg_path covers the whole component; a
		// product-scope conclusion additionally has no component PURL. Both
		// must be expanded to every matching scan finding because the consumer
		// emits one ModifiedFinding per finding it filters, including path.
		if e.ComponentPURL != "" && e.PkgPath != "" {
			expectedByKey[canonicalKey(FindingKey{
				Product:         e.ProductDigest,
				VulnerabilityID: e.VulnerabilityID,
				ComponentPURL:   e.ComponentPURL,
				PkgPath:         e.PkgPath,
			})] = e
			continue
		}
		for _, f := range findingsForConclusion(scans, e) {
			expectedByKey[canonicalKey(FindingKey{
				Product:         e.ProductDigest,
				VulnerabilityID: e.VulnerabilityID,
				ComponentPURL:   f.ComponentPURL,
				PkgPath:         f.PkgPath,
			})] = ExpectedHit{
				ProductDigest:   e.ProductDigest,
				VulnerabilityID: e.VulnerabilityID,
				ComponentPURL:   f.ComponentPURL,
				PkgPath:         f.PkgPath,
				ExpectedStatus:  e.ExpectedStatus,
			}
		}
	}

	report := &RoundTripReport{
		ExpectedCount:  len(expected),
		MissingHits:    []string{},
		UnexpectedHits: []string{},
		StatusMismatch: []string{},
	}
	observedByKey := map[FindingKey]HitObservation{}

	for si := range scans {
		s := &scans[si]
		hex := digestHex(s.Product.RepoDigests[0])
		trivyReport, err := buildTrivyReport(s)
		if err != nil {
			return nil, err
		}

		if err := vex.Filter(ctx, trivyReport, vex.Options{
			Sources: []vex.Source{{Type: vex.TypeFile, FilePath: docSource}},
		}); err != nil {
			return nil, xerrors.Errorf("consumer round-trip on %s: %w", s.Product.RepoDigests[0], err)
		}

		for _, res := range trivyReport.Results {
			for _, mf := range res.ModifiedFindings {
				v, ok := mf.Finding.(types.DetectedVulnerability)
				if !ok {
					continue
				}
				key := FindingKey{
					Product:         hex,
					VulnerabilityID: v.VulnerabilityID,
					ComponentPURL:   purlString(v.PkgIdentifier.PURL),
					PkgPath:         v.PkgPath,
				}
				observedByKey[canonicalKey(key)] = HitObservation{
					ProductDigest:   hex,
					VulnerabilityID: v.VulnerabilityID,
					ComponentPURL:   key.ComponentPURL,
					PkgPath:         v.PkgPath,
					Status:          string(mf.Status),
					// The consumer records the VEX file path it was given.
					// Reduce it to the document basename so the report never
					// embeds a machine-local absolute path.
					Source: filepath.Base(mf.Source),
				}
			}
		}
	}

	report.Observations = make([]HitObservation, 0, len(observedByKey))
	for _, k := range sortedObserved(observedByKey) {
		report.Observations = append(report.Observations, observedByKey[k])
	}
	report.ObservedCount = len(observedByKey)

	// Expected but not observed.
	for key, e := range expectedByKey {
		obs, ok := observedByKey[key]
		if !ok {
			report.MissingHits = append(report.MissingHits, fmt.Sprintf(
				"%s expected %s on %s", key.String(), e.ExpectedStatus, e.ComponentPURL))
			continue
		}
		if obs.Status != e.ExpectedStatus {
			report.StatusMismatch = append(report.StatusMismatch, fmt.Sprintf(
				"%s expected status %s but consumer returned %s", key.String(), e.ExpectedStatus, obs.Status))
		}
	}
	// Observed but not expected: the document filtered something it should not.
	for key := range observedByKey {
		if _, ok := expectedByKey[key]; !ok {
			report.UnexpectedHits = append(report.UnexpectedHits, key.String())
		}
	}
	sort.Strings(report.MissingHits)
	sort.Strings(report.UnexpectedHits)
	sort.Strings(report.StatusMismatch)

	if report.ObservedCount == 0 {
		return report, xerrors.New("round-trip failure: consumer produced zero hits; document did not match any finding")
	}
	return report, nil
}

// canonicalKey normalizes representation differences that are irrelevant to
// PURL/digest identity but would break string-set comparison:
//   - product keys reduce a full repo digest to its bare hex
//   - component PURLs are re-rendered through the purl parser so percent
//     encoding (e.g. "+" vs "%2B") is canonical on both sides
func canonicalKey(k FindingKey) FindingKey {
	out := k
	out.Product = digestHex(k.Product)
	if p, err := packageurl.FromString(k.ComponentPURL); err == nil {
		out.ComponentPURL = p.String()
	}
	return out
}

// findingsForConclusion expands a non-path-pinned conclusion to the concrete
// scan findings it covers: all components for product scope, or the named
// component's occurrences for component scope.
func findingsForConclusion(scans []ScanResult, e ExpectedHit) []ScanFinding {
	var out []ScanFinding
	for si := range scans {
		s := &scans[si]
		if digestHex(s.Product.RepoDigests[0]) != e.ProductDigest {
			continue
		}
		for _, f := range s.Findings {
			if f.VulnerabilityID != e.VulnerabilityID {
				continue
			}
			if e.ComponentPURL == "" || f.ComponentPURL == e.ComponentPURL {
				out = append(out, f)
			}
		}
	}
	return out
}

// Product-scope expected rows have no component PURL; at comparison time they
// are expanded per observed component by matching on product+vuln only.
func findingsForProduct(scans []ScanResult, hex, vulnID string) []ScanFinding {
	var out []ScanFinding
	for si := range scans {
		s := &scans[si]
		if digestHex(s.Product.RepoDigests[0]) != hex {
			continue
		}
		for _, f := range s.Findings {
			if f.VulnerabilityID == vulnID {
				out = append(out, f)
			}
		}
	}
	return out
}

func sortedObserved(m map[FindingKey]HitObservation) []FindingKey {
	keys := make([]FindingKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	return keys
}

func purlString(p *packageurl.PackageURL) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// buildTrivyReport converts a ScanResult into the types.Report shape the real
// consumer expects, including a connected component tree (image root ->
// application/OS node -> components) so leaf-to-root traversal reaches the OCI
// root PURL the document statements use as the product.
func buildTrivyReport(s *ScanResult) (*types.Report, error) {
	if _, _, err := digestFromRepoDigest(s.Product.RepoDigests[0]); err != nil {
		return nil, err
	}

	packages := make([]ftypes.Package, 0, len(s.Findings))
	vulns := make([]types.DetectedVulnerability, 0, len(s.Findings))
	seenPkg := map[string]bool{}
	uidSeq := 0

	for _, f := range s.Findings {
		p, err := packageurl.FromString(f.ComponentPURL)
		if err != nil {
			return nil, xerrors.Errorf("rehydrate %s: %w", f.ComponentPURL, err)
		}
		purlCopy := p
		uid := ""
		if !seenPkg[f.ComponentPURL] {
			uidSeq++
			uid = fmt.Sprintf("pkg-%d", uidSeq)
			seenPkg[f.ComponentPURL] = true
			packages = append(packages, ftypes.Package{
				ID:           f.ComponentName + "@" + f.InstalledVersion,
				Name:         f.ComponentName,
				Version:      f.InstalledVersion,
				Relationship: ftypes.RelationshipIndirect,
				Identifier: ftypes.PkgIdentifier{
					UID:    uid,
					BOMRef: f.ComponentPURL,
					PURL:   &purlCopy,
				},
			})
		} else {
			for _, pkg := range packages {
				if pkg.Identifier.BOMRef == f.ComponentPURL {
					uid = pkg.Identifier.UID
					break
				}
			}
		}
		vulns = append(vulns, types.DetectedVulnerability{
			VulnerabilityID:  f.VulnerabilityID,
			PkgName:          f.ComponentName,
			PkgPath:          f.PkgPath,
			InstalledVersion: f.InstalledVersion,
			PkgIdentifier: ftypes.PkgIdentifier{
				UID:    uid,
				BOMRef: f.ComponentPURL,
				PURL:   &purlCopy,
			},
		})
	}

	report := &types.Report{
		ArtifactName: s.Product.Name,
		ArtifactType: ftypes.TypeContainerImage,
		Metadata: types.Metadata{
			RepoTags:    s.Product.RepoTags,
			RepoDigests: s.Product.RepoDigests,
			ImageConfig: v1Config(s.Product.Architecture),
		},
		Results: types.Results{
			{
				Target:          s.Product.Name,
				Class:           types.ClassOSPkg,
				Type:            ftypes.Debian,
				Packages:        packages,
				Vulnerabilities: vulns,
			},
		},
	}
	return report, nil
}
