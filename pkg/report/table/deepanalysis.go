package table

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// DeepAnalysisRenderer renders a deep vulnerability impact analysis section.
//
// For each result it produces two blocks:
//  1. Impact Analysis  – "IF this CVE is exploited → WILL result in …"
//     derived from the CVSS v3 vector fields.
//  2. Remediation Comparison – per-package before/after view showing which
//     CVEs are resolved by upgrading to the fixed version plus a net-saving
//     summary line.
type DeepAnalysisRenderer struct {
	w          *bytes.Buffer
	isTerminal bool
}

// NewDeepAnalysisRenderer creates a DeepAnalysisRenderer that writes into buf.
func NewDeepAnalysisRenderer(buf *bytes.Buffer, isTerminal bool) *DeepAnalysisRenderer {
	return &DeepAnalysisRenderer{w: buf, isTerminal: isTerminal}
}

// RenderReport iterates over all results in the report and renders the deep
// analysis blocks for every result that contains vulnerabilities.
func (r *DeepAnalysisRenderer) RenderReport(report types.Report) {
	for _, result := range report.Results {
		if len(result.Vulnerabilities) == 0 {
			continue
		}
		r.renderResult(result)
	}
}

// renderResult renders both analysis blocks for a single scan result.
func (r *DeepAnalysisRenderer) renderResult(result types.Result) {
	r.renderImpactAnalysis(result)
	r.renderRemediationComparison(result)
}

// ─────────────────────────────────────────────────────────────────
// Block 1: Impact Analysis
// ─────────────────────────────────────────────────────────────────

func (r *DeepAnalysisRenderer) renderImpactAnalysis(result types.Result) {
	title := fmt.Sprintf("Deep Impact Analysis — %s", result.Target)
	r.printSectionTitle(title)

	tw := newTableWriter(r.w, r.isTerminal)
	tw.SetHeaders("CVE ID", "Package", "Severity", "IF Exploited → Attack Vector", "WILL Result In")

	for _, v := range result.Vulnerabilities {
		vector := bestCVSSVector(v)
		attackVector, impact := ParseCVSSImpact(vector)
		sev := v.Severity
		sevStr := sev
		if r.isTerminal {
			sevStr = ColorizeSeverity(sev, sev)
		}
		tw.AddRow(v.VulnerabilityID, v.PkgName, sevStr, attackVector, impact)
	}

	tw.Render()
	_, _ = fmt.Fprintln(r.w)
}

// bestCVSSVector picks the best available CVSS vector for a vulnerability,
// preferring v3 over v4 over v2.
func bestCVSSVector(v types.DetectedVulnerability) string {
	// Try each source for a v3 vector first
	for _, cvss := range v.CVSS {
		if cvss.V3Vector != "" {
			return cvss.V3Vector
		}
	}
	for _, cvss := range v.CVSS {
		if cvss.V40Vector != "" {
			return cvss.V40Vector
		}
	}
	for _, cvss := range v.CVSS {
		if cvss.V2Vector != "" {
			return cvss.V2Vector
		}
	}
	return ""
}

// ParseCVSSImpact derives human-readable attack-vector and impact strings from
// a CVSS v2/v3 vector string.
//
// CVSS v3 example:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
// CVSS v2 example:  AV:N/AC:L/Au:N/C:C/I:C/A:C
func ParseCVSSImpact(vector string) (attackVector, impact string) {
	if vector == "" {
		return "Unknown", "Unknown"
	}

	// Strip the "CVSS:3.x/" or "CVSS:4.x/" prefix if present
	if idx := strings.Index(vector, "/"); idx != -1 {
		if strings.HasPrefix(vector, "CVSS:") {
			vector = vector[idx+1:]
		}
	}

	metrics := parseMetrics(vector)

	// ── Attack Vector ──────────────────────────────────────────
	av := metrics["AV"]
	switch av {
	case "N":
		attackVector = "Network (remotely exploitable, no physical access needed)"
	case "A":
		attackVector = "Adjacent Network (requires network adjacency)"
	case "L":
		attackVector = "Local (requires local access or user interaction)"
	case "P":
		attackVector = "Physical (requires physical access to device)"
	default:
		attackVector = "Unknown"
	}

	// ── Privileges Required ────────────────────────────────────
	pr := metrics["PR"]
	var privStr string
	switch pr {
	case "N":
		privStr = "no authentication required"
	case "L":
		privStr = "low privileges required"
	case "H":
		privStr = "admin/high privileges required"
	default:
		// CVSS v2 uses "Au" for authentication
		switch metrics["Au"] {
		case "N":
			privStr = "no authentication required"
		case "S":
			privStr = "single authentication required"
		case "M":
			privStr = "multiple authentications required"
		default:
			privStr = ""
		}
	}

	// ── Impact (C/I/A) ─────────────────────────────────────────
	var impacts []string

	c := metrics["C"]
	switch c {
	case "H", "C":
		impacts = append(impacts, "complete confidentiality breach (data exposure)")
	case "L", "P":
		impacts = append(impacts, "partial confidentiality breach")
	}

	i := metrics["I"]
	switch i {
	case "H", "C":
		impacts = append(impacts, "complete integrity violation (data tampering / code execution)")
	case "L", "P":
		impacts = append(impacts, "partial integrity violation")
	}

	a := metrics["A"]
	switch a {
	case "H", "C":
		impacts = append(impacts, "complete availability loss (service disruption / DoS)")
	case "L", "P":
		impacts = append(impacts, "partial availability loss")
	}

	if len(impacts) == 0 {
		impact = "No direct impact on C/I/A"
	} else {
		impact = strings.Join(impacts, "; ")
	}

	if privStr != "" {
		impact = fmt.Sprintf("[%s] %s", privStr, impact)
	}

	return attackVector, impact
}

// parseMetrics splits a CVSS metric string (e.g. "AV:N/AC:L/PR:N/…") into a
// map of metric-key → metric-value.
func parseMetrics(vector string) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	return m
}

// ─────────────────────────────────────────────────────────────────
// Block 2: Remediation Comparison
// ─────────────────────────────────────────────────────────────────

type pkgInfo struct {
	name             string
	installedVersion string
	fixedVersion     string // best (non-empty) fixed version across all vulns for this pkg
	vulns            []types.DetectedVulnerability
}

func (r *DeepAnalysisRenderer) renderRemediationComparison(result types.Result) {
	title := fmt.Sprintf("Remediation Comparison — %s", result.Target)
	r.printSectionTitle(title)

	pkgs := groupByPackage(result.Vulnerabilities)

	tw := newTableWriter(r.w, r.isTerminal)
	tw.SetHeaders("Package", "BEFORE (current state)", "AFTER FIX (resolved CVEs)", "Net Gain")

	totalFixed := 0
	total := len(result.Vulnerabilities)

	for _, pkg := range pkgs {
		// BEFORE column
		sev := countSeverities(pkg.vulns)
		beforeParts := []string{fmt.Sprintf("%s@%s", pkg.name, pkg.installedVersion)}
		for _, sevName := range dbTypes.SeverityNames {
			if n := sev[sevName]; n > 0 {
				if r.isTerminal {
					beforeParts = append(beforeParts, ColorizeSeverity(fmt.Sprintf("%s:%d", sevName, n), sevName))
				} else {
					beforeParts = append(beforeParts, fmt.Sprintf("%s:%d", sevName, n))
				}
			}
		}
		beforeStr := strings.Join(beforeParts, "  ")

		// AFTER column
		var fixableCVEs []string
		var unfixableCVEs []string
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
		} else if r.isTerminal {
			netStr = color.New(color.FgGreen).Sprint(netStr)
		}

		tw.AddRow(pkg.name, beforeStr, afterStr, netStr)
		totalFixed += resolved
	}

	tw.Render()

	// Net improvement summary
	upgradeable := countPackagesWithFix(pkgs)
	summary := fmt.Sprintf(
		"\nSummary: Upgrading %d package(s) will eliminate %d of %d vulnerabilities detected.\n",
		upgradeable, totalFixed, total,
	)
	if r.isTerminal {
		summary = color.New(color.FgCyan).Sprint(summary)
	}
	_, _ = fmt.Fprint(r.w, summary)
}

// groupByPackage aggregates vulnerabilities into per-package structs, sorted
// by package name for deterministic output.
func groupByPackage(vulns []types.DetectedVulnerability) []pkgInfo {
	pkgMap := make(map[string]*pkgInfo)
	for _, v := range vulns {
		key := v.PkgName + "@" + v.InstalledVersion
		p, ok := pkgMap[key]
		if !ok {
			p = &pkgInfo{
				name:             v.PkgName,
				installedVersion: v.InstalledVersion,
			}
			pkgMap[key] = p
		}
		p.vulns = append(p.vulns, v)
		// Keep the highest (lexicographically last) non-empty fixed version.
		// In practice callers should deduplicate, but this is a safe fallback.
		if v.FixedVersion != "" && v.FixedVersion > p.fixedVersion {
			p.fixedVersion = v.FixedVersion
		}
	}

	result := make([]pkgInfo, 0, len(pkgMap))
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

// countSeverities returns a map of severity name → count for a slice of vulns.
func countSeverities(vulns []types.DetectedVulnerability) map[string]int {
	m := make(map[string]int)
	for _, v := range vulns {
		m[v.Severity]++
	}
	return m
}

// countPackagesWithFix returns how many packages have at least one fixable CVE.
func countPackagesWithFix(pkgs []pkgInfo) int {
	n := 0
	for _, p := range pkgs {
		if p.fixedVersion != "" {
			n++
		}
	}
	return n
}

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

func (r *DeepAnalysisRenderer) printSectionTitle(title string) {
	border := strings.Repeat("─", len(title)+4)
	if r.isTerminal {
		_, _ = fmt.Fprintf(r.w, "\n%s\n", color.New(color.FgCyan, color.Bold).Sprint("┌"+border+"┐"))
		_, _ = fmt.Fprintf(r.w, "%s\n", color.New(color.FgCyan, color.Bold).Sprintf("│  %s  │", title))
		_, _ = fmt.Fprintf(r.w, "%s\n\n", color.New(color.FgCyan, color.Bold).Sprint("└"+border+"┘"))
	} else {
		_, _ = fmt.Fprintf(r.w, "\n%s\n", strings.Repeat("=", len(title)))
		_, _ = fmt.Fprintf(r.w, "%s\n", title)
		_, _ = fmt.Fprintf(r.w, "%s\n\n", strings.Repeat("=", len(title)))
	}
}
