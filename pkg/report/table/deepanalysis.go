package table

// deepanalysis.go — COORDINATOR
//
// DeepAnalysisRenderer is the entry-point for the deep vulnerability analysis
// output.  It is intentionally thin: it delegates all work to the two
// dedicated modules:
//
//   - CheckModule (deepcheck.go) — CHECK phase: exploitability + impact analysis
//   - FixModule   (deepfix.go)   — FIX phase:   remediation comparison
//
// Adding new analysis phases in the future should be done by creating a new
// dedicated file/struct and wiring it here, NOT by adding logic to this file.

import (
"bytes"
"fmt"
"strings"

"github.com/fatih/color"

"github.com/aquasecurity/trivy/pkg/types"
)

// DeepAnalysisRenderer coordinates the CHECK and FIX module renderers.
type DeepAnalysisRenderer struct {
check *CheckModule
fix   *FixModule
}

// NewDeepAnalysisRenderer creates a DeepAnalysisRenderer writing into buf.
func NewDeepAnalysisRenderer(buf *bytes.Buffer, isTerminal bool) *DeepAnalysisRenderer {
return &DeepAnalysisRenderer{
check: NewCheckModule(buf, isTerminal),
fix:   NewFixModule(buf, isTerminal),
}
}

// RenderReport iterates over all results in the report and renders the deep
// analysis output for every result that contains vulnerabilities.
func (r *DeepAnalysisRenderer) RenderReport(report types.Report) {
for _, result := range report.Results {
if len(result.Vulnerabilities) == 0 {
continue
}
r.check.RenderCheck(result)
r.fix.RenderFix(result)
}
}

// ─────────────────────────────────────────────────────────────────
// Shared rendering helper used by both CheckModule and FixModule
// ─────────────────────────────────────────────────────────────────

// printSectionHeader writes a framed section title to w.
// Both CheckModule and FixModule call this to keep visual consistency.
func printSectionHeader(w *bytes.Buffer, isTerminal bool, title string) {
border := strings.Repeat("─", len(title)+4)
if isTerminal {
_, _ = fmt.Fprintf(w, "\n%s\n", color.New(color.FgCyan, color.Bold).Sprint("┌"+border+"┐"))
_, _ = fmt.Fprintf(w, "%s\n", color.New(color.FgCyan, color.Bold).Sprintf("│  %s  │", title))
_, _ = fmt.Fprintf(w, "%s\n\n", color.New(color.FgCyan, color.Bold).Sprint("└"+border+"┘"))
} else {
_, _ = fmt.Fprintf(w, "\n%s\n", strings.Repeat("=", len(title)))
_, _ = fmt.Fprintf(w, "%s\n", title)
_, _ = fmt.Fprintf(w, "%s\n\n", strings.Repeat("=", len(title)))
}
}
