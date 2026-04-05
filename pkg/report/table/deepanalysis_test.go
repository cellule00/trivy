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
	sevs := make([]dbTypes.Severity, 0, len(dbTypes.SeverityNames))
	for _, name := range dbTypes.SeverityNames {
		s, err := dbTypes.NewSeverity(name)
		if err != nil {
			// SeverityNames is a package-level constant slice; any parse error here
			// indicates a bug in the trivy-db package itself.
			panic("unexpected unknown severity name: " + name)
		}
		sevs = append(sevs, s)
	}
	return sevs
}

// makeVuln is a helper to build a DetectedVulnerability with a CVSS v3 vector.
func makeVuln(cveID, pkg, installed, fixed, severity, cvssV3 string) types.DetectedVulnerability {
	v := types.DetectedVulnerability{
		VulnerabilityID:  cveID,
		PkgName:          pkg,
		InstalledVersion: installed,
		FixedVersion:     fixed,
	}
	v.Severity = severity
	if cvssV3 != "" {
		v.CVSS = dbTypes.VendorCVSS{
			"nvd": dbTypes.CVSS{V3Vector: cvssV3},
		}
	}
	return v
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
// DeepAnalysisRenderer integration tests
// ─────────────────────────────────────────────────────────────────

func TestDeepAnalysisRenderer_ImpactAndRemediation(t *testing.T) {
	buf := &bytes.Buffer{}
	renderer := table.NewDeepAnalysisRenderer(buf, false /* not terminal */)

	now := time.Now()
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
		CreatedAt: now,
	}

	renderer.RenderReport(report)
	output := buf.String()

	// Impact Analysis block
	assert.Contains(t, output, "Deep Impact Analysis")
	assert.Contains(t, output, "CVE-2021-0001")
	assert.Contains(t, output, "Network")
	assert.Contains(t, output, "confidentiality breach")

	// Remediation Comparison block
	assert.Contains(t, output, "Remediation Comparison")
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
	// Nothing should be written when there are no vulnerabilities
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
	assert.Equal(t, 2, strings.Count(output, "Deep Impact Analysis"))
	assert.Equal(t, 2, strings.Count(output, "Remediation Comparison"))
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
	assert.Contains(t, output, "Deep Impact Analysis")
	assert.Contains(t, output, "Remediation Comparison")
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
	assert.NotContains(t, output, "Deep Impact Analysis")
	assert.NotContains(t, output, "Remediation Comparison")
}
