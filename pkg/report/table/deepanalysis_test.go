package table_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

// allSeverities returns a slice of all known severities for use in table.Options.
func allSeverities() []dbTypes.Severity {
	severities := make([]dbTypes.Severity, 0, len(dbTypes.SeverityNames))
	for _, name := range dbTypes.SeverityNames {
		s, err := dbTypes.NewSeverity(name)
		if err != nil {
			panic("unexpected unknown severity name: " + name)
		}
		severities = append(severities, s)
	}
	return severities
}

// makeVuln is a helper to build a DetectedVulnerability with a CVSS v3 vector.
func makeVuln(cveID, pkg, installed, fixed, severity, cvssV3 string) types.DetectedVulnerability {
	vuln := types.DetectedVulnerability{
		VulnerabilityID:  cveID,
		PkgName:          pkg,
		InstalledVersion: installed,
		FixedVersion:     fixed,
	}
	vuln.Severity = severity
	if cvssV3 != "" {
		vuln.CVSS = dbTypes.VendorCVSS{
			"nvd": dbTypes.CVSS{V3Vector: cvssV3},
		}
	}
	return vuln
}

// makeVulnWithScore builds a DetectedVulnerability with a CVSS v3 vector AND numeric score.
func makeVulnWithScore(cveID, pkg, installed, fixed, severity, cvssV3 string, v3Score float64) types.DetectedVulnerability {
	vuln := types.DetectedVulnerability{
		VulnerabilityID:  cveID,
		PkgName:          pkg,
		InstalledVersion: installed,
		FixedVersion:     fixed,
	}
	vuln.Severity = severity
	if cvssV3 != "" {
		vuln.CVSS = dbTypes.VendorCVSS{
			"nvd": dbTypes.CVSS{V3Vector: cvssV3, V3Score: v3Score},
		}
	}
	return vuln
}


// ─────────────────────────────────────────────────────────────────
// ParseCVSSImpact tests
// ─────────────────────────────────────────────────────────────────

func TestParseCVSSImpact_NetworkNoAuth_FullCIA(t *testing.T) {
	av, impact := table.ParseCVSSImpact("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.Contains(t, av, "Network")
	assert.Contains(t, impact, "no authentication required")
	assert.Contains(t, impact, "confidentiality breach")
	assert.Contains(t, impact, "integrity violation")
	assert.Contains(t, impact, "availability loss")
}

func TestParseCVSSImpact_LocalHighPriv_PartialImpact(t *testing.T) {
	av, impact := table.ParseCVSSImpact("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:L")
	assert.Contains(t, av, "Local")
	assert.Contains(t, impact, "admin/high privileges required")
	assert.Contains(t, impact, "partial confidentiality")
	assert.NotContains(t, impact, "integrity violation")
	assert.Contains(t, impact, "partial availability")
}

func TestParseCVSSImpact_AdjacentNoImpact(t *testing.T) {
	av, impact := table.ParseCVSSImpact("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:N")
	assert.Contains(t, av, "Adjacent")
	assert.Contains(t, impact, "No direct impact")
}

func TestParseCVSSImpact_Physical(t *testing.T) {
	av, _ := table.ParseCVSSImpact("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.Contains(t, av, "Physical")
}

func TestParseCVSSImpact_EmptyVector(t *testing.T) {
	av, impact := table.ParseCVSSImpact("")
	assert.Equal(t, "Unknown", av)
	assert.Equal(t, "Unknown", impact)
}

func TestParseCVSSImpact_CVSSv2(t *testing.T) {
	// CVSS v2 vectors have no "CVSS:" prefix
	av, impact := table.ParseCVSSImpact("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	assert.Contains(t, av, "Network")
	assert.Contains(t, impact, "no authentication required")
}

// ─────────────────────────────────────────────────────────────────
// ExploitLikelihood tests
// ─────────────────────────────────────────────────────────────────

func TestExploitLikelihood_Critical(t *testing.T) {
	// Network, low complexity, no privileges, no user interaction → CRITICAL
	l := table.ExploitLikelihood("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.Equal(t, "CRITICAL", l)
}

func TestExploitLikelihood_HighNoUserInteraction(t *testing.T) {
	// Network, low complexity, low privileges, no UI → HIGH
	l := table.ExploitLikelihood("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
	assert.Equal(t, "HIGH", l)
}

func TestExploitLikelihood_HighUserRequired(t *testing.T) {
	// Network, low complexity, no privileges, but needs user click → HIGH
	l := table.ExploitLikelihood("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N")
	assert.Equal(t, "HIGH", l)
}

func TestExploitLikelihood_HighComplexNoAuth(t *testing.T) {
	// Network, HIGH complexity but no auth + no UI → HIGH
	l := table.ExploitLikelihood("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")
	assert.Equal(t, "HIGH", l)
}

func TestExploitLikelihood_MediumNetworkRestricted(t *testing.T) {
	// Network, but high complexity AND requires privileges → MEDIUM
	l := table.ExploitLikelihood("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
	assert.Equal(t, "MEDIUM", l)
}

func TestExploitLikelihood_MediumAdjacent(t *testing.T) {
	l := table.ExploitLikelihood("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.Equal(t, "MEDIUM", l)
}

func TestExploitLikelihood_LowLocal(t *testing.T) {
	l := table.ExploitLikelihood("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.Equal(t, "LOW", l)
}

func TestExploitLikelihood_LowPhysical(t *testing.T) {
	l := table.ExploitLikelihood("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.Equal(t, "LOW", l)
}

func TestExploitLikelihood_UnknownEmptyVector(t *testing.T) {
	l := table.ExploitLikelihood("")
	assert.Equal(t, "UNKNOWN", l)
}

func TestExploitLikelihood_CVSSv2NoAuth(t *testing.T) {
	// CVSS v2: Au:N maps to no-privileges → network no-auth should be CRITICAL
	l := table.ExploitLikelihood("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	assert.Equal(t, "CRITICAL", l)
}

// ─────────────────────────────────────────────────────────────────
// CheckModule tests
// ─────────────────────────────────────────────────────────────────

func TestCheckModule_RendersExploitSurfaceAndImpact(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)

	result := types.Result{
		Target: "test-image (debian 11)",
		Class:  types.ClassOSPkg,
		Vulnerabilities: []types.DetectedVulnerability{
			makeVuln("CVE-2021-0001", "libfoo", "1.0.0", "1.0.1", "CRITICAL",
				"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
		},
	}

	m.RenderCheck(result)
	out := buf.String()

	// Exploit Surface table
	assert.Contains(t, out, "CHECK — Exploit Surface")
	assert.Contains(t, out, "Attack Vector")
	assert.Contains(t, out, "Complexity")
	assert.Contains(t, out, "Auth / Privileges")
	assert.Contains(t, out, "User Interaction")
	assert.Contains(t, out, "Exploit Likelihood")
	assert.Contains(t, out, "CRITICAL")
	assert.Contains(t, out, "Network")
	assert.Contains(t, out, "no authentication required")
	assert.Contains(t, out, "None (no user action needed)")

	// Impact Assessment table
	assert.Contains(t, out, "CHECK — Impact Assessment")
	assert.Contains(t, out, "Confidentiality")
	assert.Contains(t, out, "Integrity")
	assert.Contains(t, out, "Availability")
	assert.Contains(t, out, "Scope")
	assert.Contains(t, out, "WILL Result In")
	assert.Contains(t, out, "High") // C/I/A columns
	assert.Contains(t, out, "Unchanged")
}

func TestCheckModule_NoVulnerabilities_NoOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)
	m.RenderCheck(types.Result{Target: "empty", Class: types.ClassOSPkg})
	assert.Empty(t, buf.String())
}

func TestCheckModule_ScopeChanged(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)
	result := types.Result{
		Target: "test",
		Vulnerabilities: []types.DetectedVulnerability{
			makeVuln("CVE-2022-1111", "lib", "1.0", "2.0", "HIGH",
				"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
		},
	}
	m.RenderCheck(result)
	out := buf.String()
	assert.Contains(t, out, "Changed (other components affected)")
}

// BUG-1 regression: privilegesLabel used to return "Unknown" when no auth field
// was present, causing impact strings to be incorrectly prefixed with "[Unknown]".
func TestCheckModule_NoPrivilegesField_NoBracketUnknownPrefix(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)
	// Vector has no PR and no Au field at all — edge case (e.g. incomplete data)
	result := types.Result{
		Target: "test",
		Vulnerabilities: []types.DetectedVulnerability{
			// Manually construct a vuln with a raw partial vector via empty CVSS map
			{
				VulnerabilityID:  "CVE-2099-0001",
				PkgName:          "pkg",
				InstalledVersion: "1.0",
				// No CVSS entry at all → bestCVSSVector returns "" → privilegesLabel("") = ""
			},
		},
	}
	m.RenderCheck(result)
	out := buf.String()
	assert.NotContains(t, out, "[Unknown]", "impact must not have [Unknown] prefix when no auth info is available")
}

// BUG-2 regression: CVSS v2 AC:M should produce "Medium" not "Unknown".
func TestExploitLikelihood_CVSSv2MediumComplexity(t *testing.T) {
	// CVSS v2: AC:M — medium complexity; network, no auth → should be MEDIUM
	l := table.ExploitLikelihood("AV:N/AC:M/Au:N/C:P/I:P/A:P")
	// AC:M in v2 is not Low, so falls into MEDIUM bucket
	assert.Equal(t, "MEDIUM", l)
}

func TestCheckModule_AttackComplexityMedium(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)
	result := types.Result{
		Target: "test",
		Vulnerabilities: []types.DetectedVulnerability{
			{
				VulnerabilityID:  "CVE-2005-0001",
				PkgName:          "oldlib",
				InstalledVersion: "1.0",
				Vulnerability: dbTypes.Vulnerability{
					Severity: "MEDIUM",
					CVSS: dbTypes.VendorCVSS{
						"nvd": dbTypes.CVSS{V2Vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
					},
				},
			},
		},
	}
	m.RenderCheck(result)
	out := buf.String()
	assert.Contains(t, out, "Medium (some conditions required)", "CVSS v2 AC:M should render as Medium")
	assert.NotContains(t, out, "Unknown", "AC:M must not fall through to Unknown")
}

// BUG-3 regression: bestCVSSVector must be deterministic when multiple vendors
// provide v3 vectors. It should prefer NVD and otherwise pick the highest score.
func TestCheckModule_BestCVSSVector_PrefersNVD(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)

	// NVD has a network (high-severity) vector; RHEL has a local (low-severity) one.
	// The output must consistently reflect the NVD vector (Network).
	result := types.Result{
		Target: "test",
		Vulnerabilities: []types.DetectedVulnerability{
			{
				VulnerabilityID:  "CVE-2024-0001",
				PkgName:          "multivendor",
				InstalledVersion: "1.0",
				Vulnerability: dbTypes.Vulnerability{
					Severity: "CRITICAL",
					CVSS: dbTypes.VendorCVSS{
						"nvd":  dbTypes.CVSS{V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8},
						"rhel": dbTypes.CVSS{V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", V3Score: 7.8},
					},
				},
			},
		},
	}

	// Run 20 times to surface any non-determinism from map iteration.
	for i := 0; i < 20; i++ {
		buf.Reset()
		m.RenderCheck(result)
		out := buf.String()
		assert.Contains(t, out, "Network", "must always pick NVD (Network) vector, not RHEL (Local)")
		assert.NotContains(t, out, "Local (requires local access", "RHEL local vector must never win over NVD")
	}
}

func TestCheckModule_BestCVSSVector_HighestScoreWinsWhenNoNVD(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)

	// No NVD entry; two vendors — pick the one with the higher score.
	result := types.Result{
		Target: "test",
		Vulnerabilities: []types.DetectedVulnerability{
			{
				VulnerabilityID:  "CVE-2024-0002",
				PkgName:          "pkg",
				InstalledVersion: "1.0",
				Vulnerability: dbTypes.Vulnerability{
					Severity: "HIGH",
					CVSS: dbTypes.VendorCVSS{
						"vendor-a": dbTypes.CVSS{V3Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 8.4},
						"vendor-b": dbTypes.CVSS{V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8},
					},
				},
			},
		},
	}

	for i := 0; i < 20; i++ {
		buf.Reset()
		m.RenderCheck(result)
		out := buf.String()
		assert.Contains(t, out, "Network", "highest-score vector (vendor-b, AV:N) must always win")
	}
}

// BUG-4: CVSS Score column should appear in Exploit Surface table.
func TestCheckModule_CVSSScoreColumn_Present(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)
	result := types.Result{
		Target: "test",
		Vulnerabilities: []types.DetectedVulnerability{
			makeVulnWithScore("CVE-2023-1234", "openssl", "1.0", "1.1", "CRITICAL",
				"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
		},
	}
	m.RenderCheck(result)
	out := buf.String()
	assert.Contains(t, out, "CVSS Score", "Exploit Surface table must have CVSS Score column header")
	assert.Contains(t, out, "9.8 (v3)", "NVD v3 score must appear in table")
}

func TestCheckModule_CVSSScoreColumn_NoScore_ShowsNA(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewCheckModule(buf, false)
	result := types.Result{
		Target: "test",
		Vulnerabilities: []types.DetectedVulnerability{
			// No CVSS at all
			{VulnerabilityID: "CVE-2023-0000", PkgName: "pkg"},
		},
	}
	m.RenderCheck(result)
	out := buf.String()
	assert.Contains(t, out, "CVSS Score")
	assert.Contains(t, out, "N/A", "missing score should display N/A")
}

// ─────────────────────────────────────────────────────────────────
// FixModule tests
// ─────────────────────────────────────────────────────────────────

func TestFixModule_RendersRemediationComparison(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewFixModule(buf, false)

	result := types.Result{
		Target: "test (alpine 3.16)",
		Class:  types.ClassOSPkg,
		Vulnerabilities: []types.DetectedVulnerability{
			makeVuln("CVE-2021-0001", "libfoo", "1.0.0", "1.0.1", "CRITICAL", ""),
			makeVuln("CVE-2021-0002", "libfoo", "1.0.0", "1.0.1", "HIGH", ""),
			makeVuln("CVE-2021-0003", "libbar", "2.0.0", "", "MEDIUM", ""),
		},
	}

	m.RenderFix(result)
	out := buf.String()

	assert.Contains(t, out, "FIX — Remediation Comparison")
	assert.Contains(t, out, "libfoo")
	assert.Contains(t, out, "Upgrade to libfoo@1.0.1")
	assert.Contains(t, out, "CVE-2021-0001")
	assert.Contains(t, out, "CVE-2021-0002")
	assert.Contains(t, out, "No fix available")
	assert.Contains(t, out, "CVE-2021-0003")
	assert.Contains(t, out, "Upgrading")
	assert.Contains(t, out, "vulnerabilities")
}

func TestFixModule_NoVulnerabilities_NoOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	m := table.NewFixModule(buf, false)
	m.RenderFix(types.Result{Target: "empty", Class: types.ClassOSPkg})
	assert.Empty(t, buf.String())
}

// ─────────────────────────────────────────────────────────────────
// DeepAnalysisRenderer integration tests
// ─────────────────────────────────────────────────────────────────

func TestDeepAnalysisRenderer_CheckAndFix(t *testing.T) {
	buf := &bytes.Buffer{}
	renderer := table.NewDeepAnalysisRenderer(buf, false /* not terminal */)

	report := types.Report{
		ArtifactName: "test-image:latest",
		Results: types.Results{
			{
				Target: "test-image:latest (debian 11)",
				Class:  types.ClassOSPkg,
				Vulnerabilities: []types.DetectedVulnerability{
					makeVuln("CVE-2021-0001", "libfoo", "1.0.0", "1.0.1", "CRITICAL",
						"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
					makeVuln("CVE-2021-0002", "libfoo", "1.0.0", "1.0.1", "HIGH",
						"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
					makeVuln("CVE-2021-0003", "libbar", "2.0.0", "", "MEDIUM",
						"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N"),
				},
			},
		},
		CreatedAt: time.Time{},
	}

	renderer.RenderReport(report)
	output := buf.String()

	// CHECK module blocks
	assert.Contains(t, output, "CHECK — Exploit Surface")
	assert.Contains(t, output, "CHECK — Impact Assessment")
	assert.Contains(t, output, "CVE-2021-0001")
	assert.Contains(t, output, "Network")
	assert.Contains(t, output, "confidentiality breach")

	// FIX module block
	assert.Contains(t, output, "FIX — Remediation Comparison")
	assert.Contains(t, output, "libfoo")
	assert.Contains(t, output, "1.0.0")
	assert.Contains(t, output, "Upgrade to libfoo@1.0.1")
	assert.Contains(t, output, "CVE-2021-0001")
	assert.Contains(t, output, "CVE-2021-0002")

	// Unfixable CVE
	assert.Contains(t, output, "No fix available")
	assert.Contains(t, output, "CVE-2021-0003")

	// Summary line
	assert.Contains(t, output, "Upgrading")
	assert.Contains(t, output, "vulnerabilities")
}

func TestDeepAnalysisRenderer_NoVulnerabilities(t *testing.T) {
	buf := &bytes.Buffer{}
	renderer := table.NewDeepAnalysisRenderer(buf, false)

	report := types.Report{
		Results: types.Results{
			{
				Target: "clean-image:latest",
				Class:  types.ClassOSPkg,
				// No vulnerabilities
			},
		},
	}

	renderer.RenderReport(report)
	assert.Empty(t, buf.String())
}

func TestDeepAnalysisRenderer_MultipleResults(t *testing.T) {
	buf := &bytes.Buffer{}
	renderer := table.NewDeepAnalysisRenderer(buf, false)

	report := types.Report{
		Results: types.Results{
			{
				Target: "os-packages (debian 11)",
				Class:  types.ClassOSPkg,
				Vulnerabilities: []types.DetectedVulnerability{
					makeVuln("CVE-2022-1111", "openssl", "1.1.1k", "1.1.1l", "HIGH",
						"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
				},
			},
			{
				Target: "usr/local/lib/python3.9/site-packages/pip (python)",
				Class:  types.ClassLangPkg,
				Vulnerabilities: []types.DetectedVulnerability{
					makeVuln("CVE-2022-2222", "pip", "21.0", "21.3", "MEDIUM",
						"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
				},
			},
		},
	}

	renderer.RenderReport(report)
	output := buf.String()

	assert.Contains(t, output, "os-packages")
	assert.Contains(t, output, "python")
	// Each result gets a CHECK Exploit Surface + CHECK Impact Assessment + FIX Remediation → 3 sections per result
	assert.Equal(t, 2, strings.Count(output, "CHECK — Exploit Surface"))
	assert.Equal(t, 2, strings.Count(output, "CHECK — Impact Assessment"))
	assert.Equal(t, 2, strings.Count(output, "FIX — Remediation Comparison"))
}

// ─────────────────────────────────────────────────────────────────
// table.Writer integration — ShowImpact flag wiring
// ─────────────────────────────────────────────────────────────────

func TestTableWriter_ShowImpact_Enabled(t *testing.T) {
	buf := &bytes.Buffer{}
	w := table.NewWriter(table.Options{
		Output:     buf,
		Scanners:   types.Scanners{types.VulnerabilityScanner},
		Severities: allSeverities(),
		TableModes: []types.TableMode{types.Detailed},
		ShowImpact: true,
	})
	require.NotNil(t, w)

	report := types.Report{
		Results: types.Results{
			{
				Target: "test (alpine 3.16)",
				Class:  types.ClassOSPkg,
				Vulnerabilities: []types.DetectedVulnerability{
					makeVuln("CVE-2023-9999", "musl", "1.2.2", "1.2.3", "CRITICAL",
						"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
				},
			},
		},
	}

	err := w.Write(context.Background(), report)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "CHECK — Exploit Surface")
	assert.Contains(t, output, "CHECK — Impact Assessment")
	assert.Contains(t, output, "FIX — Remediation Comparison")
}

func TestTableWriter_ShowImpact_Disabled(t *testing.T) {
	buf := &bytes.Buffer{}
	w := table.NewWriter(table.Options{
		Output:     buf,
		Scanners:   types.Scanners{types.VulnerabilityScanner},
		Severities: allSeverities(),
		TableModes: []types.TableMode{types.Detailed},
		ShowImpact: false,
	})
	require.NotNil(t, w)

	report := types.Report{
		Results: types.Results{
			{
				Target: "test (alpine 3.16)",
				Class:  types.ClassOSPkg,
				Vulnerabilities: []types.DetectedVulnerability{
					makeVuln("CVE-2023-9999", "musl", "1.2.2", "1.2.3", "CRITICAL",
						"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
				},
			},
		},
	}

	err := w.Write(context.Background(), report)
	require.NoError(t, err)

	output := buf.String()
	assert.NotContains(t, output, "CHECK — Exploit Surface")
	assert.NotContains(t, output, "CHECK — Impact Assessment")
	assert.NotContains(t, output, "FIX — Remediation Comparison")
}
