package vexgen

import (
	openvex "github.com/openvex/go-vex/pkg/vex"
)

// ExpectationsFromDocument reconstructs the consumer-trustable expectation set
// from a generated OpenVEX document and the scan results. It exists so the
// standalone `roundtrip` subcommand can verify a document without the original
// review sheets. Product-scope statements (no subcomponent) expand to every
// matching component finding, mirroring the consumer's traversal.
func ExpectationsFromDocument(scans []ScanResult, doc *openvex.VEX) map[FindingKey]ConvergedConclusion {
	// Map each product's OCI PURL (exact and the version-less variant) back to
	// its digest hex.
	byPURL := map[string]string{}
	for si := range scans {
		s := &scans[si]
		pp, err := productPURL(s.Product)
		if err != nil {
			continue
		}
		hex := digestHex(s.Product.RepoDigests[0])
		byPURL[pp] = hex
		if vless, err := versionlessPURL(pp); err == nil {
			byPURL[vless] = hex
		}
	}

	out := map[FindingKey]ConvergedConclusion{}
	for _, stmt := range doc.Statements {
		status := string(stmt.Status)
		if status != string(openvex.StatusNotAffected) && status != string(openvex.StatusFixed) {
			continue
		}
		vuln := string(stmt.Vulnerability.Name)
		for _, prod := range stmt.Products {
			hex, ok := byPURL[prod.ID]
			if !ok {
				continue
			}
			if len(prod.Subcomponents) == 0 {
				// Product scope: expand to every component finding.
				for _, f := range findingsForProduct(scans, hex, vuln) {
					k := FindingKey{Product: hex, VulnerabilityID: vuln, ComponentPURL: f.ComponentPURL, PkgPath: f.PkgPath}
					out[k] = ConvergedConclusion{
						Scope:           ScopeProduct,
						ProductDigest:   hex,
						VulnerabilityID: vuln,
						ComponentPURL:   f.ComponentPURL,
						PkgPath:         f.PkgPath,
						Status:          status,
						Justification:   string(stmt.Justification),
					}
				}
				continue
			}
			for _, sc := range prod.Subcomponents {
				for _, f := range findingsForComponent(scans, hex, vuln, sc.ID) {
					k := FindingKey{Product: hex, VulnerabilityID: vuln, ComponentPURL: f.ComponentPURL, PkgPath: f.PkgPath}
					out[k] = ConvergedConclusion{
						Scope:           ScopeComponent,
						ProductDigest:   hex,
						VulnerabilityID: vuln,
						ComponentPURL:   f.ComponentPURL,
						PkgPath:         f.PkgPath,
						Status:          status,
						Justification:   string(stmt.Justification),
					}
				}
			}
		}
	}
	return out
}

// findingsForComponent returns scan findings for a vulnerability on a
// component, tolerating a version-less subcomponent PURL via name matching.
func findingsForComponent(scans []ScanResult, hex, vuln, stmtPURL string) []ScanFinding {
	var out []ScanFinding
	want, err := packageurlParse(stmtPURL)
	if err != nil {
		return out
	}
	for si := range scans {
		s := &scans[si]
		if digestHex(s.Product.RepoDigests[0]) != hex {
			continue
		}
		for _, f := range s.Findings {
			if f.VulnerabilityID != vuln {
				continue
			}
			got, err := packageurlParse(f.ComponentPURL)
			if err != nil {
				continue
			}
			sameID := got.Type == want.Type && got.Namespace == want.Namespace && got.Name == want.Name
			sameVersion := want.Version == "" || want.Version == got.Version
			if sameID && sameVersion {
				out = append(out, f)
			}
		}
	}
	return out
}
