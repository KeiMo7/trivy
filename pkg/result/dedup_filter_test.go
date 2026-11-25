package result_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
)

// TestFilterResult_IgnoredAndDedupCoexist covers the case where the same CVE
// appears twice: one occurrence is matched by .trivyignore and the other is
// not. The ignored occurrence must land in ModifiedFindings and leave the
// candidate set, while the non-ignored occurrence survives de-duplication in
// Vulnerabilities. Ignored findings never disappear because of de-duplication.
func TestFilterResult_IgnoredAndDedupCoexist(t *testing.T) {
	t.Parallel()

	severities := []dbTypes.Severity{dbTypes.SeverityHigh}

	// Two distinct five-tuples (different PkgPath) so both survive dedup.
	ignoredVuln := vuln("CVE-2024-9000", "pkg-id", "lib", "1.0", "1.1", "ignored/path.jar", "HIGH")
	keptVuln := vuln("CVE-2024-9000", "pkg-id", "lib", "1.0", "1.1", "kept/path.jar", "HIGH")

	res := &types.Result{
		Target:          "app",
		Vulnerabilities: []types.DetectedVulnerability{ignoredVuln, keptVuln},
	}

	ignoreConf := result.IgnoreConfig{
		FilePath: "testdata/.trivyignore",
		Vulnerabilities: result.IgnoreFindings{
			{
				ID:        "CVE-2024-9000",
				Paths:     []string{"ignored/path.jar"},
				Statement: "accepted risk",
			},
		},
	}

	result.FilterResult(t.Context(), res, ignoreConf, result.FilterOptions{
		Severities: severities,
	})

	// The non-ignored occurrence remains in the report.
	require.Len(t, res.Vulnerabilities, 1)
	assert.Equal(t, "kept/path.jar", res.Vulnerabilities[0].PkgPath)

	// The ignored occurrence was recorded as a modified finding.
	require.Len(t, res.ModifiedFindings, 1)
	modified := res.ModifiedFindings[0]
	assert.Equal(t, types.FindingStatusIgnored, modified.Status)
	detected, ok := modified.Finding.(types.DetectedVulnerability)
	require.True(t, ok)
	assert.Equal(t, "ignored/path.jar", detected.PkgPath)
	assert.Equal(t, "CVE-2024-9000", detected.VulnerabilityID)
}

// TestFilterResult_AllOccurrencesIgnored verifies that when every occurrence is
// ignored, the vulnerability leaves the candidate set entirely but every
// ignored copy is still retained in ModifiedFindings.
func TestFilterResult_AllOccurrencesIgnored(t *testing.T) {
	t.Parallel()

	v1 := vuln("CVE-2024-9001", "pkg-id", "lib", "1.0", "1.1", "a.jar", "HIGH")
	v2 := vuln("CVE-2024-9001", "pkg-id-2", "lib", "1.0", "1.1", "b.jar", "HIGH")

	res := &types.Result{
		Target:          "app",
		Vulnerabilities: []types.DetectedVulnerability{v1, v2},
	}

	ignoreConf := result.IgnoreConfig{
		Vulnerabilities: result.IgnoreFindings{
			{ID: "CVE-2024-9001"},
		},
	}

	result.FilterResult(t.Context(), res, ignoreConf, result.FilterOptions{
		Severities: []dbTypes.Severity{dbTypes.SeverityHigh},
	})

	assert.Nil(t, res.Vulnerabilities, "all occurrences ignored leave the candidate set")
	assert.Len(t, res.ModifiedFindings, 2, "both ignored copies are retained")
}
