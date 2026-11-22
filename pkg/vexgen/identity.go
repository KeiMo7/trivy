package vexgen

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

// Identity helpers. These deliberately mirror Trivy's own identifier
// construction (pkg/purl parseOCI and the component PURLs in the scan result)
// so the generated document lands inside the consumer's existing matching
// semantics without any consumer-side change.

// digestFromRepoDigest splits "example.com/repo/app@sha256:abcd" into the
// repository ("example.com/repo/app") and the digest ("sha256:abcd").
func digestFromRepoDigest(repoDigest string) (repo, digest string, err error) {
	idx := strings.LastIndex(repoDigest, "@")
	if idx <= 0 || idx == len(repoDigest)-1 {
		return "", "", fmt.Errorf("malformed repo digest %q: expected repo@digest", repoDigest)
	}
	repo = repoDigest[:idx]
	digest = repoDigest[idx+1:]
	if !strings.HasPrefix(digest, "sha256:") {
		return "", "", fmt.Errorf("malformed repo digest %q: digest must be a sha256 digest", repoDigest)
	}
	return repo, digest, nil
}

// digestHex returns the bare hex portion of a digest. It accepts both a bare
// digest ("sha256:abcd") and a full repo digest ("repo@sha256:abcd").
func digestHex(digest string) string {
	if _, d, found := strings.Cut(digest, "@"); found {
		digest = d
	}
	return strings.TrimPrefix(digest, "sha256:")
}

// productPURL builds the OCI PURL exactly like Trivy's purl.parseOCI:
//
//	pkg:oci/<last path segment>@sha256:<hex>?repository_url=<full repo>&arch=<arch>
//
// The version is the content digest, so re-tagging the same image yields the
// same PURL and therefore the same product identity.
func productPURL(p Product) (string, error) {
	if len(p.RepoDigests) == 0 {
		return "", fmt.Errorf("product %q has no repo digest: content identity cannot be established", p.Name)
	}
	repo, digest, err := digestFromRepoDigest(p.RepoDigests[0])
	if err != nil {
		return "", err
	}

	name := strings.ToLower(repo)
	if _, base, found := strings.CutLast(name, "/"); found {
		name = base
	}

	qualifiers := packageurl.Qualifiers{
		{Key: "repository_url", Value: repo},
	}
	if p.Architecture != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "arch", Value: p.Architecture})
	}

	purl := packageurl.NewPackageURL(packageurl.TypeOCI, "", name, digest, qualifiers, "")
	return purl.String(), nil
}

// versionlessPURL drops the version segment of a PURL. The consumer's
// PurlMatches treats a version-less statement PURL as matching any scanned
// version, but the generator keeps versions on component statements and only
// uses the version-less form where broad matching is intended. Returns the
// input unchanged if it cannot be parsed.
func versionlessPURL(raw string) (string, error) {
	p, err := packageurl.FromString(raw)
	if err != nil {
		return "", fmt.Errorf("invalid component PURL %q: %w", raw, err)
	}
	p.Version = ""
	return p.String(), nil
}

// purlVersion extracts the version segment for staleness comparison.
func purlVersion(raw string) (string, error) {
	p, err := packageurl.FromString(raw)
	if err != nil {
		return "", fmt.Errorf("invalid component PURL %q: %w", raw, err)
	}
	return p.Version, nil
}

// packageurlParse is a thin parse wrapper returning the packageurl type used
// across identity comparisons.
func packageurlParse(raw string) (packageurl.PackageURL, error) {
	return packageurl.FromString(raw)
}
