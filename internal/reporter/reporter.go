package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/matthias/auditter/internal/analyzer"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorBgRed   = "\033[41m"
	colorBgGreen = "\033[42m"
)

const reportWidth = 74

// PackageInfo holds metadata about the audited package for display.
type PackageInfo struct {
	License      string   `json:"license,omitempty"`
	Maintainers  []string `json:"maintainers,omitempty"`
	RepoURL      string   `json:"repository_url,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	TotalVersions int    `json:"total_versions"`
	Dependencies  int    `json:"dependencies"`
	HasScripts    bool   `json:"has_scripts"`
}

// Report holds the complete audit results.
type Report struct {
	Package   string            `json:"package"`
	Version   string            `json:"version"`
	Results   []analyzer.Result `json:"results"`
	Score     int               `json:"risk_score"`
	Info      PackageInfo       `json:"package_info"`
	AuditedAt string            `json:"audited_at"`
}

// ProjectReport holds audit results for multiple packages.
type ProjectReport struct {
	ProjectName string   `json:"project_name,omitempty"`
	Reports     []Report `json:"reports"`
	TotalScore  int      `json:"total_risk_score"`
}
// Reporter outputs audit results to a writer.
type Reporter struct {
	writer io.Writer
	format string
	lang   Language
}

// Formats
const (
	FormatTerminal = "terminal"
	FormatJSON     = "json"
	FormatMarkdown = "markdown"
	FormatHTML     = "html"
	FormatCSV      = "csv"
	FormatPDF      = "pdf"
)

// New creates a new Reporter.
func New(w io.Writer, format string, lang Language) *Reporter {
	if format == "" {
		format = FormatTerminal
	}
	if lang == "" {
		lang = LangEN
	}
	return &Reporter{writer: w, format: format, lang: lang}
}

// Render outputs the report.
func (r *Reporter) Render(report Report) error {
	report.Score = CalculateRiskScore(report.Results)
	report.AuditedAt = time.Now().UTC().Format(time.RFC3339)

	switch r.format {
	case FormatJSON:
		return r.renderJSON(report)
	case FormatMarkdown:
		return r.renderMarkdown(report)
	case FormatHTML:
		return r.renderHTML(report)
	case FormatCSV:
		return r.renderCSV(report)
	case FormatPDF:
		return r.renderPDF(report)
	default:
		return r.renderTerminal(report)
	}
}

// RenderProject outputs a project-wide report.
func (r *Reporter) RenderProject(projectReport ProjectReport) error {
	if r.format == FormatJSON {
		enc := json.NewEncoder(r.writer)
		enc.SetIndent("", "  ")
		return enc.Encode(projectReport)
	}

	if r.format == FormatPDF {
		return r.renderProjectPDF(projectReport)
	}

	// For other formats, we just iterate for now or create a summary
	fmt.Fprintf(r.writer, "Project Audit: %s\n", projectReport.ProjectName)
	fmt.Fprintf(r.writer, "Packages Audited: %d\n\n", len(projectReport.Reports))

	for _, report := range projectReport.Reports {
		if err := r.Render(report); err != nil {
			return err
		}
		fmt.Fprintln(r.writer, "\n"+strings.Repeat("=", reportWidth)+"\n")
	}

	return nil
}

func (r *Reporter) renderProjectPDF(projectReport ProjectReport) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Arial", "I", 8)
		pdf.Cell(0, 10, fmt.Sprintf("Project Audit: %s", projectReport.ProjectName))
		pdf.Ln(10)
	})

	for _, report := range projectReport.Reports {
		r.addReportToPDF(pdf, report)
	}

	pdf.SetY(-15)
	pdf.SetFont("Arial", "I", 8)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 10, r.T("audited_at", time.Now().UTC().Format(time.RFC3339)), "", 0, "C", false, 0, "")

	return pdf.Output(r.writer)
}

func (r *Reporter) addReportToPDF(pdf *fpdf.Fpdf, report Report) {
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, r.T("title"))
	pdf.Ln(12)

	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, r.T("pkg_info"))
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("%s: %s@%s", r.T("package"), report.Package, report.Version))
	pdf.Ln(6)
	if report.Info.License != "" {
		pdf.Cell(0, 6, fmt.Sprintf("%s: %s", r.T("license"), report.Info.License))
		pdf.Ln(6)
	}
	pdf.Cell(0, 6, fmt.Sprintf("%s: %d %s", r.T("versions"), report.Info.TotalVersions, r.T("published")))
	pdf.Ln(6)
	pdf.Cell(0, 6, fmt.Sprintf("%s: %d %s", r.T("dependencies"), report.Info.Dependencies, r.T("direct")))
	pdf.Ln(10)

	_, scoreLabel := r.GetRiskLevel(report.Score)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, r.T("risk_assessment"))
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("%s (%s)", scoreLabel, r.T("score_label", report.Score)))
	pdf.Ln(10)

	allFindings := collectFindings(report.Results)
	if len(allFindings) > 0 {
		pdf.SetFont("Arial", "B", 12)
		pdf.Cell(40, 10, r.T("findings_summary"))
		pdf.Ln(10)

		for _, f := range allFindings {
			pdf.SetFont("Arial", "B", 10)
			pdf.SetTextColor(200, 0, 0)
			pdf.Cell(0, 6, fmt.Sprintf("[%s] %s", f.Severity, f.Title))
			pdf.SetTextColor(0, 0, 0)
			pdf.Ln(6)

			pdf.SetFont("Arial", "I", 9)
			pdf.Cell(0, 6, r.T("analyzer_label", f.Analyzer))
			pdf.Ln(6)

			pdf.SetFont("Arial", "", 9)
			pdf.MultiCell(0, 5, f.Description, "", "", false)
			pdf.Ln(2)

			if f.ExploitExample != "" {
				pdf.SetFont("Arial", "B", 9)
				pdf.Cell(0, 6, r.T("attack_scenario"))
				pdf.Ln(6)
				pdf.SetFont("Courier", "", 8)
				pdf.SetFillColor(240, 240, 240)
				pdf.MultiCell(0, 4, f.ExploitExample, "", "", true)
				pdf.Ln(2)
			}

			if f.Remediation != "" {
				pdf.SetFont("Arial", "B", 9)
				pdf.Cell(0, 6, r.T("remediation"))
				pdf.Ln(6)
				pdf.SetFont("Arial", "", 9)
				pdf.MultiCell(0, 5, f.Remediation, "", "", false)
				pdf.Ln(2)
			}
			pdf.Ln(4)
		}
	} else {
		pdf.SetFont("Arial", "I", 10)
		pdf.SetTextColor(0, 128, 0)
		pdf.Cell(0, 10, r.T("no_issues"))
	}
}

func (r *Reporter) renderJSON(report Report) error {
	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func (r *Reporter) renderTerminal(report Report) error {
	w := r.writer

	// ── Title Box ──
	r.printBox(w, " "+r.T("title"), colorCyan)
	fmt.Fprintln(w)

	// ── Package Info ──
	r.printSectionHeader(w, r.T("pkg_info"))
	r.printField(w, r.T("package"), report.Package+"@"+report.Version)
	if report.Info.License != "" {
		r.printField(w, r.T("license"), report.Info.License)
	}
	if len(report.Info.Maintainers) > 0 {
		r.printField(w, r.T("maintainers"), strings.Join(report.Info.Maintainers, ", "))
	}
	if report.Info.RepoURL != "" {
		r.printField(w, r.T("repository"), report.Info.RepoURL)
	}
	if report.Info.CreatedAt != "" {
		r.printField(w, r.T("created"), report.Info.CreatedAt)
	}
	r.printField(w, r.T("versions"), fmt.Sprintf("%d %s", report.Info.TotalVersions, r.T("published")))
	r.printField(w, r.T("dependencies"), fmt.Sprintf("%d %s", report.Info.Dependencies, r.T("direct")))
	if report.Info.HasScripts {
		r.printField(w, r.T("install_scripts"), fmt.Sprintf("%s%s%s", colorRed, r.T("scripts_yes"), colorReset))
	} else {
		r.printField(w, r.T("install_scripts"), fmt.Sprintf("%s%s%s", colorGreen, r.T("scripts_none"), colorReset))
	}
	fmt.Fprintln(w)

	// ── Risk Score with visual bar ──
	scoreColor, scoreLabel := r.GetRiskLevel(report.Score)
	r.printSectionHeader(w, r.T("risk_assessment"))
	fmt.Fprintf(w, "  %s%s%s\n", colorBold, scoreLabel, colorReset)
	fmt.Fprintf(w, "  %s\n\n", r.T("score_label", report.Score))
	r.printRiskBar(w, report.Score, scoreColor)
	fmt.Fprintln(w)

	// ── Analyzer Errors ──
	hasErrors := false
	for _, result := range report.Results {
		if result.Err != nil {
			if !hasErrors {
				r.printSectionHeader(w, r.T("analyzer_errors"))
				hasErrors = true
			}
			fmt.Fprintf(w, "  %s! %s: %s%s\n", colorYellow, result.AnalyzerName, result.Err, colorReset)
		}
	}
	if hasErrors {
		fmt.Fprintln(w)
	}

	// ── Collect and sort findings ──
	allFindings := collectFindings(report.Results)
	if len(allFindings) == 0 {
		r.printBox(w, " "+r.T("no_issues"), colorGreen)
		fmt.Fprintln(w)
		return nil
	}

	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Severity > allFindings[j].Severity
	})

	// ── Findings Summary ──
	severityCounts := map[analyzer.Severity]int{}
	for _, f := range allFindings {
		severityCounts[f.Severity]++
	}

	r.printSectionHeader(w, r.T("findings_summary"))
	fmt.Fprintf(w, "  %s\n\n", r.T("total_findings", len(allFindings), countActiveAnalyzers(report.Results)))

	if c := severityCounts[analyzer.SeverityCritical]; c > 0 {
		fmt.Fprintf(w, "  %s%s  %s  %s %d %s\n", colorBold, colorBgRed, r.T("severity_critical"), colorReset, c, r.pluralize(r.T("finding_plural"), c))
	}
	if c := severityCounts[analyzer.SeverityHigh]; c > 0 {
		fmt.Fprintf(w, "  %s  %s      %s %d %s\n", colorRed, r.T("severity_high"), colorReset, c, r.pluralize(r.T("finding_plural"), c))
	}
	if c := severityCounts[analyzer.SeverityMedium]; c > 0 {
		fmt.Fprintf(w, "  %s  %s    %s %d %s\n", colorYellow, r.T("severity_medium"), colorReset, c, r.pluralize(r.T("finding_plural"), c))
	}
	if c := severityCounts[analyzer.SeverityLow]; c > 0 {
		fmt.Fprintf(w, "  %s  %s       %s %d %s\n", colorDim, r.T("severity_low"), colorReset, c, r.pluralize(r.T("finding_plural"), c))
	}
	fmt.Fprintln(w)

	// ── Detailed Findings by Severity ──
	severityOrder := []analyzer.Severity{
		analyzer.SeverityCritical,
		analyzer.SeverityHigh,
		analyzer.SeverityMedium,
		analyzer.SeverityLow,
	}

	for _, sev := range severityOrder {
		findings := filterBySeverity(allFindings, sev)
		if len(findings) == 0 {
			continue
		}

		sevColor := severityColor(sev)
		label := r.T("findings_count", r.GetSeverityLabel(sev), len(findings))
		fmt.Fprintf(w, "%s%s%s %s %s\n", colorBold, sevColor, severityIcon(sev), label, colorReset)
		fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", reportWidth), colorReset)

		for i, f := range findings {
			fmt.Fprintf(w, "\n  %s%s%s %s%s\n",
				colorBold, sevColor, severityIcon(sev), f.Title, colorReset)
			fmt.Fprintf(w, "  %s%s%s\n", colorDim, r.T("analyzer_label", f.Analyzer), colorReset)
			r.printWrapped(w, f.Description, "  ", reportWidth)

			if f.ExploitExample != "" {
				fmt.Fprintln(w)
				fmt.Fprintf(w, "  %s%s%s%s\n", colorBold, colorMagenta, r.T("attack_scenario"), colorReset)
				for _, line := range strings.Split(f.ExploitExample, "\n") {
					fmt.Fprintf(w, "  %s%s%s\n", colorMagenta, line, colorReset)
				}
			}

			if f.Remediation != "" {
				fmt.Fprintln(w)
				fmt.Fprintf(w, "  %s%s%s%s\n", colorBold, colorGreen, r.T("remediation"), colorReset)
				r.printWrapped(w, f.Remediation, "  ", reportWidth)
			}

			if i < len(findings)-1 {
				fmt.Fprintf(w, "\n  %s%s%s\n", colorDim, strings.Repeat("·", reportWidth-4), colorReset)
			}
		}
		fmt.Fprintf(w, "\n%s%s%s\n\n", colorDim, strings.Repeat("─", reportWidth), colorReset)
	}

	// ── Per-Analyzer Breakdown ──
	r.printSectionHeader(w, r.T("analyzer_breakdown"))
	r.printAnalyzerBreakdown(w, report.Results)
	fmt.Fprintln(w)

	// ── Recommendations ──
	r.printRecommendations(w, report.Score, allFindings)

	// ── Footer ──
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("═", reportWidth), colorReset)
	fmt.Fprintf(w, "%s%s%s\n\n", colorDim, r.T("audited_at", report.AuditedAt), colorReset)

	return nil
}

func (r *Reporter) renderMarkdown(report Report) error {
	w := r.writer
	fmt.Fprintf(w, "# %s\n\n", r.T("title"))
	fmt.Fprintf(w, "## %s\n\n", r.T("pkg_info"))
	fmt.Fprintf(w, "- **%s**: %s@%s\n", r.T("package"), report.Package, report.Version)
	if report.Info.License != "" {
		fmt.Fprintf(w, "- **%s**: %s\n", r.T("license"), report.Info.License)
	}
	fmt.Fprintf(w, "- **%s**: %d %s\n", r.T("versions"), report.Info.TotalVersions, r.T("published"))
	fmt.Fprintf(w, "- **%s**: %d %s\n", r.T("dependencies"), report.Info.Dependencies, r.T("direct"))
	
	scoreColor, scoreLabel := r.GetRiskLevel(report.Score)
	_ = scoreColor // Not used in Markdown
	fmt.Fprintf(w, "\n## %s\n\n", r.T("risk_assessment"))
	fmt.Fprintf(w, "### %s\n", scoreLabel)
	fmt.Fprintf(w, "%s\n\n", r.T("score_label", report.Score))

	allFindings := collectFindings(report.Results)
	if len(allFindings) == 0 {
		fmt.Fprintf(w, "> %s\n\n", r.T("no_issues"))
	} else {
		fmt.Fprintf(w, "## %s\n\n", r.T("findings_summary"))
		fmt.Fprintf(w, "| %s | %s |\n", r.T("severity_critical"), r.T("severity_high"))
		fmt.Fprintf(w, "| --- | --- |\n")
		// ... simpler markdown for now
		fmt.Fprintf(w, "\n### %s\n\n", r.T("findings_summary"))
		for _, f := range allFindings {
			fmt.Fprintf(w, "#### [%s] %s\n", f.Severity, f.Title)
			fmt.Fprintf(w, "*%s*\n\n", r.T("analyzer_label", f.Analyzer))
			fmt.Fprintf(w, "%s\n\n", f.Description)
			if f.ExploitExample != "" {
				fmt.Fprintf(w, "**%s**\n\n```\n%s\n```\n\n", r.T("attack_scenario"), f.ExploitExample)
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "**%s**\n\n%s\n\n", r.T("remediation"), f.Remediation)
			}
		}
	}

	fmt.Fprintf(w, "---\n*%s*\n", r.T("audited_at", report.AuditedAt))
	return nil
}

func (r *Reporter) renderHTML(report Report) error {
	w := r.writer
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>%s</title>", r.T("title"))
	fmt.Fprintf(w, "<style>body{font-family:sans-serif;line-height:1.5;max-width:800px;margin:2em auto;padding:0 1em;} .critical{color:red;font-weight:bold;} .high{color:red;} .medium{color:orange;} .low{color:gray;} pre{background:#f4f4f4;padding:1em;overflow-x:auto;}</style></head><body>")
	fmt.Fprintf(w, "<h1>%s</h1>", r.T("title"))
	fmt.Fprintf(w, "<h2>%s</h2>", r.T("pkg_info"))
	fmt.Fprintf(w, "<ul><li><b>%s</b>: %s@%s</li><li><b>%s</b>: %s</li></ul>", r.T("package"), report.Package, report.Version, r.T("license"), report.Info.License)
	
	_, scoreLabel := r.GetRiskLevel(report.Score)
	fmt.Fprintf(w, "<h2>%s</h2>", r.T("risk_assessment"))
	fmt.Fprintf(w, "<p><b>%s</b>: %s</p>", scoreLabel, r.T("score_label", report.Score))

	allFindings := collectFindings(report.Results)
	if len(allFindings) > 0 {
		fmt.Fprintf(w, "<h2>%s</h2>", r.T("findings_summary"))
		for _, f := range allFindings {
			fmt.Fprintf(w, "<div class='%s'><h3>[%s] %s</h3>", strings.ToLower(f.Severity.String()), f.Severity, f.Title)
			fmt.Fprintf(w, "<p><i>%s</i></p>", r.T("analyzer_label", f.Analyzer))
			fmt.Fprintf(w, "<p>%s</p>", f.Description)
			if f.ExploitExample != "" {
				fmt.Fprintf(w, "<h4>%s</h4><pre>%s</pre>", r.T("attack_scenario"), f.ExploitExample)
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "<h4>%s</h4><p>%s</p>", r.T("remediation"), f.Remediation)
			}
			fmt.Fprintf(w, "</div>")
		}
	}
	fmt.Fprintf(w, "<hr><p><i>%s</i></p></body></html>", r.T("audited_at", report.AuditedAt))
	return nil
}

func (r *Reporter) renderCSV(report Report) error {
	w := r.writer
	allFindings := collectFindings(report.Results)
	fmt.Fprintln(w, "Severity,Analyzer,Title,Description")
	for _, f := range allFindings {
		fmt.Fprintf(w, "%s,%s,\"%s\",\"%s\"\n", f.Severity, f.Analyzer, strings.ReplaceAll(f.Title, "\"", "\"\""), strings.ReplaceAll(f.Description, "\"", "\"\""))
	}
	return nil
}

func (r *Reporter) renderPDF(report Report) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	r.addReportToPDF(pdf, report)

	pdf.SetY(-15)
	pdf.SetFont("Arial", "I", 8)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 10, r.T("audited_at", report.AuditedAt), "", 0, "C", false, 0, "")

	return pdf.Output(r.writer)
}
// ── Rendering Helpers ──

func (r *Reporter) printBox(w io.Writer, text string, color string) {
	inner := reportWidth - 4
	padded := text
	if len(padded) < inner {
		padded = padded + strings.Repeat(" ", inner-len(padded))
	}
	fmt.Fprintf(w, "%s%s╔%s╗%s\n", colorBold, color, strings.Repeat("═", inner+2), colorReset)
	fmt.Fprintf(w, "%s%s║ %s ║%s\n", colorBold, color, padded, colorReset)
	fmt.Fprintf(w, "%s%s╚%s╝%s\n", colorBold, color, strings.Repeat("═", inner+2), colorReset)
}

func (r *Reporter) printSectionHeader(w io.Writer, title string) {
	fmt.Fprintf(w, "%s%s┌─ %s %s%s\n", colorBold, colorWhite, title, strings.Repeat("─", reportWidth-5-len(title)), colorReset)
}

func (r *Reporter) printField(w io.Writer, label, value string) {
	fmt.Fprintf(w, "  %s%-16s%s %s\n", colorDim, label+":", colorReset, value)
}

func (r *Reporter) printRiskBar(w io.Writer, score int, color string) {
	barWidth := 40
	filled := score * barWidth / 100
	if filled > barWidth {
		filled = barWidth
	}
	empty := barWidth - filled
	fmt.Fprintf(w, "  %s%s%s%s%s %d%%\n",
		color,
		strings.Repeat("█", filled),
		colorDim,
		strings.Repeat("░", empty),
		colorReset,
		score)
}

func (r *Reporter) printWrapped(w io.Writer, text string, indent string, width int) {
	maxLen := width - len(indent) - 2
	if maxLen <= 0 {
		maxLen = 60
	}
	for _, line := range strings.Split(text, "\n") {
		for len(line) > maxLen {
			cut := strings.LastIndex(line[:maxLen], " ")
			if cut <= 0 {
				cut = maxLen
			}
			fmt.Fprintf(w, "%s%s\n", indent, line[:cut])
			line = line[cut:]
			if len(line) > 0 && line[0] == ' ' {
				line = line[1:]
			}
		}
		fmt.Fprintf(w, "%s%s\n", indent, line)
	}
}

func (r *Reporter) printAnalyzerBreakdown(w io.Writer, results []analyzer.Result) {
	// Sort by finding count descending
	type entry struct {
		name     string
		total    int
		critical int
		high     int
		medium   int
		low      int
	}
	var entries []entry
	for _, res := range results {
		e := entry{name: res.AnalyzerName}
		for _, f := range res.Findings {
			e.total++
			switch f.Severity {
			case analyzer.SeverityCritical:
				e.critical++
			case analyzer.SeverityHigh:
				e.high++
			case analyzer.SeverityMedium:
				e.medium++
			case analyzer.SeverityLow:
				e.low++
			}
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].total > entries[j].total
	})

	maxBar := 30
	maxFindings := 0
	for _, e := range entries {
		if e.total > maxFindings {
			maxFindings = e.total
		}
	}

	for _, e := range entries {
		barLen := 0
		if maxFindings > 0 {
			barLen = e.total * maxBar / maxFindings
		}
		if barLen == 0 && e.total > 0 {
			barLen = 1
		}

		bar := ""
		if e.total > 0 {
			bar = strings.Repeat("█", barLen)
		}

		fmt.Fprintf(w, "  %-18s %s%-30s%s %d", e.name, severityColorForCount(e), bar, colorReset, e.total)
		if e.total > 0 {
			parts := []string{}
			if e.critical > 0 {
				parts = append(parts, fmt.Sprintf("%dC", e.critical))
			}
			if e.high > 0 {
				parts = append(parts, fmt.Sprintf("%dH", e.high))
			}
			if e.medium > 0 {
				parts = append(parts, fmt.Sprintf("%dM", e.medium))
			}
			if e.low > 0 {
				parts = append(parts, fmt.Sprintf("%dL", e.low))
			}
			fmt.Fprintf(w, " (%s)", strings.Join(parts, " "))
		} else {
			fmt.Fprintf(w, " %s✓ %s%s", colorGreen, r.T("clean"), colorReset)
		}
		fmt.Fprintln(w)
	}
}

func (r *Reporter) printRecommendations(w io.Writer, score int, findings []analyzer.Finding) {
	r.printSectionHeader(w, r.T("recommendations"))

	recs := r.generateRecommendations(score, findings)
	for i, rec := range recs {
		fmt.Fprintf(w, "  %s%d.%s %s\n", colorBold, i+1, colorReset, rec)
	}
	fmt.Fprintln(w)
}

// ── Pure Functions ──

func severityColor(s analyzer.Severity) string {
	switch s {
	case analyzer.SeverityCritical:
		return colorRed
	case analyzer.SeverityHigh:
		return colorRed
	case analyzer.SeverityMedium:
		return colorYellow
	case analyzer.SeverityLow:
		return colorDim
	default:
		return colorWhite
	}
}

func severityIcon(s analyzer.Severity) string {
	switch s {
	case analyzer.SeverityCritical:
		return "✖"
	case analyzer.SeverityHigh:
		return "!"
	case analyzer.SeverityMedium:
		return "~"
	case analyzer.SeverityLow:
		return "-"
	default:
		return " "
	}
}

func severityColorForCount(e struct {
	name     string
	total    int
	critical int
	high     int
	medium   int
	low      int
}) string {
	if e.critical > 0 {
		return colorRed
	}
	if e.high > 0 {
		return colorRed
	}
	if e.medium > 0 {
		return colorYellow
	}
	return colorDim
}

func (r *Reporter) pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	// This is a very simple pluralization for English.
	// For other languages it might need more logic.
	if r.lang == LangEN {
		return word + "s"
	}
	// For DE, "Befund" -> "Befunde" (already handled by T key if we wanted, but let's keep it simple)
	if r.lang == LangDE {
		return r.T("findings_plural")
	}
	return word
}

func (r *Reporter) generateRecommendations(score int, findings []analyzer.Finding) []string {
	var recs []string

	if score >= 70 {
		recs = append(recs, fmt.Sprintf("%s%s%s", colorRed, r.T("rec_critical"), colorReset))
	} else if score >= 40 {
		recs = append(recs, r.T("rec_moderate"))
	}

	hasCriticalScripts := false
	hasTyposquat := false
	hasVuln := false
	hasNoBuildProvenance := false
	hasDepsIssues := false
	hasMaintainerRisk := false

	for _, f := range findings {
		switch {
		case f.Analyzer == "install-scripts" && f.Severity >= analyzer.SeverityHigh:
			hasCriticalScripts = true
		case f.Analyzer == "typosquatting":
			hasTyposquat = true
		case f.Analyzer == "vulnerabilities":
			hasVuln = true
		case f.Analyzer == "provenance" && strings.Contains(f.Title, "attestation"):
			hasNoBuildProvenance = true
		case f.Analyzer == "dependencies" && f.Severity >= analyzer.SeverityMedium:
			hasDepsIssues = true
		case f.Analyzer == "maintainers" && f.Severity >= analyzer.SeverityMedium:
			hasMaintainerRisk = true
		}
	}

	if hasCriticalScripts {
		recs = append(recs, r.T("rec_scripts"))
	}
	if hasTyposquat {
		recs = append(recs, r.T("rec_typosquat"))
	}
	if hasVuln {
		recs = append(recs, r.T("rec_vuln"))
	}
	if hasNoBuildProvenance {
		recs = append(recs, r.T("rec_provenance"))
	}
	if hasDepsIssues {
		recs = append(recs, r.T("rec_deps"))
	}
	if hasMaintainerRisk {
		recs = append(recs, r.T("rec_maintainer"))
	}

	if len(recs) == 0 {
		recs = append(recs, fmt.Sprintf("%s%s%s", colorGreen, r.T("rec_safe"), colorReset))
	}

	return recs
}

func collectFindings(results []analyzer.Result) []analyzer.Finding {
	var all []analyzer.Finding
	for _, r := range results {
		all = append(all, r.Findings...)
	}
	return all
}

func filterBySeverity(findings []analyzer.Finding, sev analyzer.Severity) []analyzer.Finding {
	var filtered []analyzer.Finding
	for _, f := range findings {
		if f.Severity == sev {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func countActiveAnalyzers(results []analyzer.Result) int {
	count := 0
	for _, r := range results {
		if r.Err == nil {
			count++
		}
	}
	return count
}

// CalculateRiskScore computes a 0-100 risk score from findings.
func CalculateRiskScore(results []analyzer.Result) int {
	score := 0
	for _, r := range results {
		for _, f := range r.Findings {
			switch f.Severity {
			case analyzer.SeverityCritical:
				score += 25
			case analyzer.SeverityHigh:
				score += 15
			case analyzer.SeverityMedium:
				score += 5
			case analyzer.SeverityLow:
				score += 2
			}
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}
