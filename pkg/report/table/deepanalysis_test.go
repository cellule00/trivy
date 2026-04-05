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
