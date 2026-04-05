package table

// deepcheck.go — CHECK MODULE
//
// Responsibility: analyse each vulnerability's exploitability and potential
// impact using CVSS v2/v3 metrics and present the findings in two read-only
// tables per scan result:
//
//  1. Exploit Surface  — HOW EASY is it to exploit?
//     Columns: Attack Vector | Complexity | Auth/Privileges | User Interaction | Exploit Likelihood
//
//  2. Impact Assessment — WHAT HAPPENS if exploited?
//     Columns: Confidentiality | Integrity | Availability | Scope | WILL Result In
//
// No remediation advice lives here.  All fix logic is in FixModule (deepfix.go).

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// CheckModule is the deep-scan CHECK phase renderer.
//
// It is deliberately stateless beyond the output buffer and terminal flag; all
// analysis is derived on-the-fly from the CVSS vectors embedded in the report.
type CheckModule struct {
	w          *bytes.Buffer
	isTerminal bool
}

// NewCheckModule returns a CheckModule that writes into buf.
func NewCheckModule(buf *bytes.Buffer, isTerminal bool) *CheckModule {
	return &CheckModule{w: buf, isTerminal: isTerminal}
}

// RenderCheck renders both CHECK sub-tables for a single scan result.
// It is a no-op when the result contains no vulnerabilities.
func (m *CheckModule) RenderCheck(result types.Result) {
	if len(result.Vulnerabilities) == 0 {
		return
	}
	m.renderExploitSurface(result)
	m.renderImpactAssessment(result)
}

// ─────────────────────────────────────────────────────────────────
// Sub-table 1: Exploit Surface
// ─────────────────────────────────────────────────────────────────

func (m *CheckModule) renderExploitSurface(result types.Result) {
	printSectionHeader(m.w, m.isTerminal,
		fmt.Sprintf("CHECK — Exploit Surface: %s", result.Target))

	tw := newTableWriter(m.w, m.isTerminal)
	tw.SetHeaders(
		"CVE ID",
		"Package",
		"Severity",
		"CVSS Score",
		"Attack Vector",
		"Complexity",
		"Auth / Privileges",
		"User Interaction",
		"Exploit Likelihood",
	)

	for _, v := range result.Vulnerabilities {
		vec := bestCVSSVector(v)
		met := parseMetrics(stripCVSSPrefix(vec))

		av := attackVectorLabel(met["AV"])
		ac := attackComplexityLabel(met["AC"])
		pr := privilegesLabel(met)
		ui := userInteractionLabel(met["UI"])

		likelihood := ExploitLikelihood(vec)
		if m.isTerminal {
			likelihood = colorizeExploitLikelihood(likelihood)
		}

		sev := v.Severity
		if m.isTerminal {
			sev = ColorizeSeverity(v.Severity, v.Severity)
		}

		score := cvssScoreLabel(v)

		tw.AddRow(v.VulnerabilityID, v.PkgName, sev, score, av, ac, pr, ui, likelihood)
	}

	tw.Render()
	_, _ = fmt.Fprintln(m.w)
}

// ─────────────────────────────────────────────────────────────────
// Sub-table 2: Impact Assessment
// ─────────────────────────────────────────────────────────────────

func (m *CheckModule) renderImpactAssessment(result types.Result) {
	printSectionHeader(m.w, m.isTerminal,
		fmt.Sprintf("CHECK — Impact Assessment: %s", result.Target))

	tw := newTableWriter(m.w, m.isTerminal)
	tw.SetHeaders(
		"CVE ID",
		"Package",
		"Confidentiality",
		"Integrity",
		"Availability",
		"Scope",
		"WILL Result In",
	)

	for _, v := range result.Vulnerabilities {
		vec := bestCVSSVector(v)
		met := parseMetrics(stripCVSSPrefix(vec))

		conf := ciaLabel(met["C"])
		integ := ciaLabel(met["I"])
		avail := ciaLabel(met["A"])
		scope := scopeLabel(met["S"])

		_, impact := ParseCVSSImpact(vec)

		tw.AddRow(v.VulnerabilityID, v.PkgName, conf, integ, avail, scope, impact)
	}

	tw.Render()
	_, _ = fmt.Fprintln(m.w)
}

// ─────────────────────────────────────────────────────────────────
// ParseCVSSImpact — public API (kept for backward compatibility)
//
// Derives human-readable attack-vector and impact strings from a CVSS
// v2/v3/v4 vector string.
//
//	CVSS v3 example:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
//	CVSS v2 example:  AV:N/AC:L/Au:N/C:C/I:C/A:C
//
// ─────────────────────────────────────────────────────────────────
func ParseCVSSImpact(vector string) (attackVector, impact string) {
	if vector == "" {
		return "Unknown", "Unknown"
	}

	met := parseMetrics(stripCVSSPrefix(vector))

	// ── Attack Vector ───────────────────────────────────────────
	attackVector = attackVectorLabel(met["AV"])

	// ── Privileges / Authentication ────────────────────────────
	privStr := privilegesLabel(met)

	// ── Impact (C/I/A) ──────────────────────────────────────────
	var parts []string

	switch met["C"] {
	case "H", "C":
		parts = append(parts, "complete confidentiality breach (data exposure)")
	case "L", "P":
		parts = append(parts, "partial confidentiality breach")
	}

	switch met["I"] {
	case "H", "C":
		parts = append(parts, "complete integrity violation (data tampering / code execution)")
	case "L", "P":
		parts = append(parts, "partial integrity violation")
	}

	switch met["A"] {
	case "H", "C":
		parts = append(parts, "complete availability loss (service disruption / DoS)")
	case "L", "P":
		parts = append(parts, "partial availability loss")
	}

	if len(parts) == 0 {
		impact = "No direct impact on C/I/A"
	} else {
		impact = strings.Join(parts, "; ")
	}

	if privStr != "" {
		impact = fmt.Sprintf("[%s] %s", privStr, impact)
	}

	return attackVector, impact
}

// ExploitLikelihood returns a risk-rated exploit likelihood string
// (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN) derived purely from CVSS metrics.
//
// The heuristic mirrors real-world exploitability scoring:
//   - CRITICAL: network-reachable, low complexity, no privileges, no user interaction
//   - HIGH:     network-reachable with one limiting factor (user click, auth, or high AC)
//   - MEDIUM:   network-reachable but significantly restricted, or adjacent-network
//   - LOW:      local or physical access required
//   - UNKNOWN:  no vector data available
func ExploitLikelihood(vector string) string {
	if vector == "" {
		return "UNKNOWN"
	}

	met := parseMetrics(stripCVSSPrefix(vector))
	av := met["AV"]
	ac := met["AC"]
	pr := met["PR"]
	ui := met["UI"]

	// CVSS v2 uses "Au" for authentication
	if pr == "" {
		switch met["Au"] {
		case "N":
			pr = "N"
		case "S":
			pr = "L"
		case "M":
			pr = "H"
		}
	}

	// For CVSS v2 vectors the UI field is absent; treat it as "N" (no user
	// interaction required) since v2 has no equivalent concept.
	noUI := ui == "N" || ui == ""

	switch av {
	case "N": // Network
		switch {
		case ac == "L" && pr == "N" && noUI:
			return "CRITICAL"
		case ac == "L" && pr == "N":
			return "HIGH" // UI=R
		case ac == "L" && noUI:
			return "HIGH" // PR=L
		case ac == "H" && pr == "N" && noUI:
			return "HIGH" // hard to exploit, but no barriers
		default:
			return "MEDIUM"
		}
	case "A": // Adjacent Network
		return "MEDIUM"
	case "L": // Local
		return "LOW"
	case "P": // Physical
		return "LOW"
	}

	return "UNKNOWN"
}

// ─────────────────────────────────────────────────────────────────
// Shared CVSS helpers — used by both CheckModule and FixModule
// ─────────────────────────────────────────────────────────────────

// bestCVSSVector returns the most descriptive CVSS vector for a vulnerability.
//
// Selection strategy (security-conservative — always picks the worst-case risk):
//  1. Prefer the NVD vendor's v3 vector when present, as it is the canonical source.
//  2. If NVD has no v3, scan all vendors and pick the v3 vector with the highest score.
//  3. Fall back to v4 vectors using the same highest-score heuristic.
//  4. Fall back to v2 vectors using the same highest-score heuristic.
//
// This ensures the output is deterministic regardless of Go map-iteration order and
// that the displayed data represents the worst-case (most dangerous) interpretation,
// which is the safest posture for a vulnerability scanner.
func bestCVSSVector(v types.DetectedVulnerability) string {
	// 1. Canonical NVD v3
	if nvd, ok := v.CVSS["nvd"]; ok && nvd.V3Vector != "" {
		return nvd.V3Vector
	}

	// 2. Highest v3 score across all vendors
	if vec := highestScoredVector(v, func(c dbTypes.CVSS) (string, float64) {
		return c.V3Vector, c.V3Score
	}); vec != "" {
		return vec
	}

	// 3. Highest v4 score across all vendors
	if vec := highestScoredVector(v, func(c dbTypes.CVSS) (string, float64) {
		return c.V40Vector, c.V40Score
	}); vec != "" {
		return vec
	}

	// 4. Highest v2 score across all vendors
	if vec := highestScoredVector(v, func(c dbTypes.CVSS) (string, float64) {
		return c.V2Vector, c.V2Score
	}); vec != "" {
		return vec
	}

	return ""
}

// highestScoredVector iterates the VendorCVSS map in a deterministic (sorted-key)
// order and returns the vector string from the entry with the highest numeric score.
// The accessor function extracts the (vector, score) pair for the desired CVSS version.
func highestScoredVector(
	v types.DetectedVulnerability,
	accessor func(dbTypes.CVSS) (string, float64),
) string {
	// Collect vendor keys so iteration is deterministic.
	keys := make([]dbTypes.SourceID, 0, len(v.CVSS))
	for k := range v.CVSS {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	best := ""
	bestScore := -1.0
	for _, k := range keys {
		vec, score := accessor(v.CVSS[k])
		if vec != "" && score > bestScore {
			best = vec
			bestScore = score
		}
	}
	return best
}

// parseMetrics splits "AV:N/AC:L/PR:N/…" into map[key]value.
func parseMetrics(vector string) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	return m
}

// stripCVSSPrefix removes the "CVSS:x.y/" prefix present in v3/v4 vectors.
func stripCVSSPrefix(vector string) string {
	if strings.HasPrefix(vector, "CVSS:") {
		if idx := strings.Index(vector, "/"); idx != -1 {
			return vector[idx+1:]
		}
	}
	return vector
}

// ─────────────────────────────────────────────────────────────────
// Metric-value to label helpers
// ─────────────────────────────────────────────────────────────────

func attackVectorLabel(av string) string {
	switch av {
	case "N":
		return "Network (remotely exploitable, no physical access needed)"
	case "A":
		return "Adjacent Network (requires network adjacency)"
	case "L":
		return "Local (requires local access or user interaction)"
	case "P":
		return "Physical (requires physical access to device)"
	default:
		return "Unknown"
	}
}

func attackComplexityLabel(ac string) string {
	switch ac {
	case "L":
		return "Low (no special conditions)"
	case "M":
		return "Medium (some conditions required)" // CVSS v2 only
	case "H":
		return "High (specific conditions required)"
	default:
		return "Unknown"
	}
}

// privilegesLabel handles both CVSS v3 (PR) and v2 (Au).
// Returns an empty string when no authentication information is present so that
// callers can omit the privilege qualifier rather than printing a misleading
// "[Unknown]" prefix.
func privilegesLabel(met map[string]string) string {
	switch met["PR"] {
	case "N":
		return "no authentication required"
	case "L":
		return "low privileges required"
	case "H":
		return "admin/high privileges required"
	}
	// CVSS v2
	switch met["Au"] {
	case "N":
		return "no authentication required"
	case "S":
		return "single authentication required"
	case "M":
		return "multiple authentications required"
	}
	return ""
}

func userInteractionLabel(ui string) string {
	switch ui {
	case "N":
		return "None (no user action needed)"
	case "R":
		return "Required (victim must take action)"
	default:
		return "N/A (CVSS v2)"
	}
}

func ciaLabel(val string) string {
	switch val {
	case "H", "C":
		return "High"
	case "L", "P":
		return "Partial"
	case "N":
		return "None"
	default:
		return "Unknown"
	}
}

func scopeLabel(s string) string {
	switch s {
	case "C":
		return "Changed (other components affected)"
	case "U":
		return "Unchanged"
	default:
		return "N/A (CVSS v2)"
	}
}

func colorizeExploitLikelihood(likelihood string) string {
	switch likelihood {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).Sprint(likelihood)
	case "HIGH":
		return color.New(color.FgHiRed).Sprint(likelihood)
	case "MEDIUM":
		return color.New(color.FgYellow).Sprint(likelihood)
	case "LOW":
		return color.New(color.FgBlue).Sprint(likelihood)
	default:
		return color.New(color.FgCyan).Sprint(likelihood)
	}
}

// cvssScoreLabel returns a human-readable CVSS score string for a vulnerability,
// e.g. "9.8 (v3)" or "7.5 (v2)". Returns "N/A" when no numeric score is available.
//
// Version preference mirrors bestCVSSVector: NVD v3 → highest v3 → highest v4 → highest v2.
func cvssScoreLabel(v types.DetectedVulnerability) string {
	// NVD v3 canonical
	if nvd, ok := v.CVSS["nvd"]; ok && nvd.V3Score > 0 {
		return fmt.Sprintf("%.1f (v3)", nvd.V3Score)
	}
	// Highest v3 across all vendors
	if score := highestNumericScore(v, func(c dbTypes.CVSS) float64 { return c.V3Score }); score > 0 {
		return fmt.Sprintf("%.1f (v3)", score)
	}
	// Highest v4
	if score := highestNumericScore(v, func(c dbTypes.CVSS) float64 { return c.V40Score }); score > 0 {
		return fmt.Sprintf("%.1f (v4)", score)
	}
	// Highest v2
	if score := highestNumericScore(v, func(c dbTypes.CVSS) float64 { return c.V2Score }); score > 0 {
		return fmt.Sprintf("%.1f (v2)", score)
	}
	return "N/A"
}

// highestNumericScore returns the maximum score returned by accessor across all
// vendors, iterating in deterministic (sorted-key) order.
func highestNumericScore(
	v types.DetectedVulnerability,
	accessor func(dbTypes.CVSS) float64,
) float64 {
	keys := make([]dbTypes.SourceID, 0, len(v.CVSS))
	for k := range v.CVSS {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	best := 0.0
	for _, k := range keys {
		if s := accessor(v.CVSS[k]); s > best {
			best = s
		}
	}
	return best
}
