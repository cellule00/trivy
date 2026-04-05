package table

// deepfix.go — FIX MODULE
//
// Responsibility: show a per-package before/after comparison that makes it
// clear which CVEs are resolved by upgrading to the fixed version and how
// many vulnerabilities are eliminated overall.
//
// The FIX module is intentionally separate from CheckModule (deepcheck.go).
// It does NOT analyse exploitability — that lives in CheckModule.
// A future "auto-fix" feature would extend this module, not CheckModule.

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// FixModule is the deep-scan FIX phase renderer.
//
// For each result it produces one table:
//
//	Remediation Comparison — per-package BEFORE/AFTER view with net gain.
//
// Logic for which CVEs are fixable vs not:
//   - A CVE is "fixable" if DetectedVulnerability.FixedVersion is non-empty.
//   - The displayed target upgrade version is the first non-empty FixedVersion
//     encountered for that package. Callers should treat this as the minimum
//     recommended version; consult the primary advisory URL for details.
type FixModule struct {
	w          *bytes.Buffer
	isTerminal bool
}

// NewFixModule returns a FixModule that writes into buf.
func NewFixModule(buf *bytes.Buffer, isTerminal bool) *FixModule {
	return &FixModule{w: buf, isTerminal: isTerminal}
}

// RenderFix renders the remediation comparison table for a single scan result.
// It is a no-op when the result contains no vulnerabilities.
func (m *FixModule) RenderFix(result types.Result) {
	if len(result.Vulnerabilities) == 0 {
		return
	}
	m.renderRemediationComparison(result)
}

// ─────────────────────────────────────────────────────────────────
// Remediation Comparison table
// ─────────────────────────────────────────────────────────────────

func (m *FixModule) renderRemediationComparison(result types.Result) {
	printSectionHeader(m.w, m.isTerminal,
		fmt.Sprintf("FIX — Remediation Comparison: %s", result.Target))

	pkgs := groupByPackage(result.Vulnerabilities)

	tw := newTableWriter(m.w, m.isTerminal)
	tw.SetHeaders("Package", "BEFORE (current state)", "AFTER FIX (resolved CVEs)", "Net Gain")

	totalFixed := 0
	total := len(result.Vulnerabilities)

	for _, pkg := range pkgs {
		// BEFORE column: package@version + severity counts
		sev := countSeverities(pkg.vulns)
		beforeParts := []string{fmt.Sprintf("%s@%s", pkg.name, pkg.installedVersion)}
		for _, sevName := range dbTypes.SeverityNames {
			if n := sev[sevName]; n > 0 {
				label := fmt.Sprintf("%s:%d", sevName, n)
				if m.isTerminal {
					label = ColorizeSeverity(label, sevName)
				}
				beforeParts = append(beforeParts, label)
			}
		}
		beforeStr := strings.Join(beforeParts, "  ")

		// AFTER column: list fixable and unfixable CVEs
		var fixableCVEs, unfixableCVEs []string
		for _, v := range pkg.vulns {
			if v.FixedVersion != "" {
				fixableCVEs = append(fixableCVEs, v.VulnerabilityID)
			} else {
				unfixableCVEs = append(unfixableCVEs, v.VulnerabilityID)
			}
		}

		var afterStr string
		if pkg.fixedVersion != "" {
			afterStr = fmt.Sprintf("Upgrade to %s@%s\nResolves: %s",
				pkg.name, pkg.fixedVersion, strings.Join(fixableCVEs, ", "))
			if len(unfixableCVEs) > 0 {
				afterStr += fmt.Sprintf("\nNo fix available: %s", strings.Join(unfixableCVEs, ", "))
			}
		} else {
			afterStr = "No fix available"
			if len(unfixableCVEs) > 0 {
				afterStr += fmt.Sprintf(" (%s)", strings.Join(unfixableCVEs, ", "))
			}
		}

		// Net gain column
		resolved := len(fixableCVEs)
		netStr := fmt.Sprintf("-%d vulnerabilities", resolved)
		if resolved == 0 {
			netStr = "No change"
		} else if m.isTerminal {
			netStr = color.New(color.FgGreen).Sprint(netStr)
		}

		tw.AddRow(pkg.name, beforeStr, afterStr, netStr)
		totalFixed += resolved
	}

	tw.Render()

	// Overall summary line
	upgradeable := countPackagesWithFix(pkgs)
	summary := fmt.Sprintf(
		"\nSummary: Upgrading %d package(s) will eliminate %d of %d vulnerabilities detected.\n",
		upgradeable, totalFixed, total,
	)
	if m.isTerminal {
		summary = color.New(color.FgCyan).Sprint(summary)
	}
	_, _ = fmt.Fprint(m.w, summary)
}

// ─────────────────────────────────────────────────────────────────
// Package grouping helpers
// ─────────────────────────────────────────────────────────────────

// fixPkgInfo groups all vulnerabilities belonging to one installed package.
type fixPkgInfo struct {
	name             string
	installedVersion string
	// fixedVersion is the first non-empty FixedVersion seen across all vulns
	// for this package.  Use the primary advisory URL for the authoritative
	// minimum required version.
	fixedVersion string
	vulns        []types.DetectedVulnerability
}

// groupByPackage aggregates vulnerabilities into per-package structs sorted
// deterministically by (name, installedVersion).
func groupByPackage(vulns []types.DetectedVulnerability) []fixPkgInfo {
	pkgMap := make(map[string]*fixPkgInfo)
	for _, v := range vulns {
		key := v.PkgName + "@" + v.InstalledVersion
		p, ok := pkgMap[key]
		if !ok {
			p = &fixPkgInfo{
				name:             v.PkgName,
				installedVersion: v.InstalledVersion,
			}
			pkgMap[key] = p
		}
		p.vulns = append(p.vulns, v)
		if v.FixedVersion != "" && p.fixedVersion == "" {
			p.fixedVersion = v.FixedVersion
		}
	}

	result := make([]fixPkgInfo, 0, len(pkgMap))
	for _, p := range pkgMap {
		result = append(result, *p)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].name != result[j].name {
			return result[i].name < result[j].name
		}
		return result[i].installedVersion < result[j].installedVersion
	})
	return result
}

// countSeverities returns a severity-name → count map for a slice of vulns.
func countSeverities(vulns []types.DetectedVulnerability) map[string]int {
	m := make(map[string]int)
	for _, v := range vulns {
		m[v.Severity]++
	}
	return m
}

// countPackagesWithFix returns how many packages have at least one fixable CVE.
func countPackagesWithFix(pkgs []fixPkgInfo) int {
	n := 0
	for _, p := range pkgs {
		if p.fixedVersion != "" {
			n++
		}
	}
	return n
}
