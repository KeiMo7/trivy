package result_test

import (
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
)

func vuln(vid, pkgID, pkgName, installed, fixed, pkgPath, severity string) types.DetectedVulnerability {
	return types.DetectedVulnerability{
		VulnerabilityID:  vid,
		PkgID:            pkgID,
		PkgName:          pkgName,
		InstalledVersion: installed,
		FixedVersion:     fixed,
		PkgPath:          pkgPath,
		Vulnerability: dbTypes.Vulnerability{
			Severity: severity,
		},
	}
}

func TestDedupVulnerabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []types.DetectedVulnerability
		want  []types.DetectedVulnerability
	}{
		{
			name:  "nil input",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty input normalizes to nil",
			input: []types.DetectedVulnerability{},
			want:  nil,
		},
		{
			name: "same five-tuple keeps larger fixed version",
			input: []types.DetectedVulnerability{
				vuln("CVE-2024-0001", "apk/alpine", "openssl", "1.0.0", "1.0.2-r0", "", "HIGH"),
				vuln("CVE-2024-0001", "apk/alpine", "openssl", "1.0.0", "", "", "HIGH"),
			},
			want: []types.DetectedVulnerability{
				vuln("CVE-2024-0001", "apk/alpine", "openssl", "1.0.0", "1.0.2-r0", "", "HIGH"),
			},
		},
		{
			name: "cross-target apk vs jar duplicates collapse on the five-tuple",
			input: []types.DetectedVulnerability{
				vuln("CVE-2024-1111", "jar/log4j", "log4j", "2.14.0", "2.17.0", "app/log4j.jar", "CRITICAL"),
				vuln("CVE-2024-1111", "apk/log4j", "log4j", "2.14.0", "2.17.1", "", "CRITICAL"),
			},
			want: []types.DetectedVulnerability{
				// Different PkgID/PkgPath => different keys => both survive.
				vuln("CVE-2024-1111", "apk/log4j", "log4j", "2.14.0", "2.17.1", "", "CRITICAL"),
				vuln("CVE-2024-1111", "jar/log4j", "log4j", "2.14.0", "2.17.0", "app/log4j.jar", "CRITICAL"),
			},
		},
		{
			name: "identical entries collapse to one",
			input: []types.DetectedVulnerability{
				vuln("CVE-2024-2222", "pkg", "bind", "9.0", "9.1", "", "MEDIUM"),
				vuln("CVE-2024-2222", "pkg", "bind", "9.0", "9.1", "", "MEDIUM"),
			},
			want: []types.DetectedVulnerability{
				vuln("CVE-2024-2222", "pkg", "bind", "9.0", "9.1", "", "MEDIUM"),
			},
		},
		{
			name: "total order: severity then pkg name then vulnerability ID then path then version",
			input: []types.DetectedVulnerability{
				vuln("CVE-LOW", "l", "zlib", "1", "", "", "LOW"),
				vuln("CVE-CRIT", "c", "zlib", "1", "", "", "CRITICAL"),
				vuln("CVE-CRIT2", "c2", "aalib", "1", "", "", "CRITICAL"),
			},
			want: []types.DetectedVulnerability{
				// Critical first, then by package name.
				vuln("CVE-CRIT2", "c2", "aalib", "1", "", "", "CRITICAL"),
				vuln("CVE-CRIT", "c", "zlib", "1", "", "", "CRITICAL"),
				vuln("CVE-LOW", "l", "zlib", "1", "", "", "LOW"),
			},
		},
		{
			name: "unknown and empty severities rank lowest and remain stable",
			input: []types.DetectedVulnerability{
				vuln("CVE-U1", "u1", "cups", "1", "", "", "UNKNOWN"),
				vuln("CVE-U2", "u2", "cups", "1", "", "", ""),
			},
			want: []types.DetectedVulnerability{
				vuln("CVE-U1", "u1", "cups", "1", "", "", "UNKNOWN"),
				vuln("CVE-U2", "u2", "cups", "1", "", "", ""),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := result.DedupVulnerabilities(tt.input)
			assert.Equal(t, tt.want, got)

			// The output must be independent of map iteration: run the same
			// input repeatedly and compare byte-identical JSON.
			var first []byte
			for range 20 {
				out, err := json.Marshal(result.DedupVulnerabilities(tt.input))
				require.NoError(t, err)
				if first == nil {
					first = out
				} else {
					assert.Equal(t, string(first), string(out))
				}
			}
		})
	}
}

func TestDedupVulnerabilitiesOrderIndependent(t *testing.T) {
	t.Parallel()

	base := []types.DetectedVulnerability{
		vuln("CVE-1", "p1", "alpha", "1.0", "1.1", "", "HIGH"),
		vuln("CVE-2", "p2", "beta", "2.0", "", "path/b.jar", "CRITICAL"),
		vuln("CVE-3", "p3", "alpha", "1.0", "1.2", "", "HIGH"),
		vuln("CVE-1", "p1", "alpha", "1.0", "1.5", "", "HIGH"), // duplicate, larger fixed wins
		vuln("CVE-4", "p4", "gamma", "3.0", "", "", "MEDIUM"),
	}

	want, err := json.Marshal(result.DedupVulnerabilities(base))
	require.NoError(t, err)

	rng := rand.New(rand.NewSource(7))
	for range 20 {
		shuffled := append([]types.DetectedVulnerability(nil), base...)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got, err := json.Marshal(result.DedupVulnerabilities(shuffled))
		require.NoError(t, err)
		assert.Equal(t, string(want), string(got))
	}
}

func TestDedupVulnerabilitiesStableEquivalentOrder(t *testing.T) {
	t.Parallel()

	// Equivalent under the ordering comparator: same severity, package name,
	// vulnerability ID, path and installed version. They are different map keys
	// only through PkgID, so both survive; SliceStable keeps input relative order.
	a := vuln("CVE-EQ", "id-a", "same", "1.0", "", "", "HIGH")
	b := vuln("CVE-EQ", "id-b", "same", "1.0", "", "", "HIGH")

	got := result.DedupVulnerabilities([]types.DetectedVulnerability{a, b})
	require.Len(t, got, 2)
	assert.Equal(t, "id-a", got[0].PkgID)
	assert.Equal(t, "id-b", got[1].PkgID)
}

func FuzzDedupVulnerabilities(f *testing.F) {
	f.Add("CVE-1", "pkg", "lib", "1.0", "1.1", "/p", uint8(0))
	f.Add("CVE-2", "", "", "", "", "", uint8(4))

	f.Fuzz(func(t *testing.T, vid, pkgID, pkgName, installed, fixed, pkgPath string, severity uint8) {
		names := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
		v := types.DetectedVulnerability{
			VulnerabilityID:  vid,
			PkgID:            pkgID,
			PkgName:          pkgName,
			InstalledVersion: installed,
			FixedVersion:     fixed,
			PkgPath:          pkgPath,
			Vulnerability: dbTypes.Vulnerability{
				Severity: names[int(severity)%len(names)],
			},
		}

		// Must never panic and must be deterministic for identical inputs.
		first := result.DedupVulnerabilities([]types.DetectedVulnerability{v, v, v})
		second := result.DedupVulnerabilities([]types.DetectedVulnerability{v, v, v})
		assert.Equal(t, first, second)
		assert.LessOrEqual(t, len(first), 1)
	})
}
