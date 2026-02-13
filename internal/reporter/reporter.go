package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/kluth/npm-security-auditter/internal/analyzer"
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
	License         string   `json:"license,omitempty"`
	Maintainers     []string `json:"maintainers,omitempty"`
	RepoURL         string   `json:"repository_url,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	TotalVersions   int      `json:"total_versions"`
	Dependencies    int      `json:"dependencies"`
	HasScripts      bool     `json:"has_scripts"`
	WeeklyDownloads int      `json:"weekly_downloads,omitempty"`
	DownloadTier    string   `json:"download_tier,omitempty"`
	IsTrustedScope  bool     `json:"is_trusted_scope,omitempty"`
	TrustedScopeOrg string   `json:"trusted_scope_org,omitempty"`
	ReputationScore int      `json:"reputation_score,omitempty"`
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
	writer  io.Writer
	format  string
	lang    Language
	verbose bool
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
	return &Reporter{writer: w, format: format, lang: lang, verbose: false}
}

// NewWithOptions creates a new Reporter with additional options.
func NewWithOptions(w io.Writer, format string, lang Language, verbose bool) *Reporter {
	r := New(w, format, lang)
	r.verbose = verbose
	return r
}

// Render outputs the report.
func (r *Reporter) Render(report Report) error {
	// Use reputation-adjusted scoring if reputation info is available
	if report.Info.WeeklyDownloads > 0 || report.Info.IsTrustedScope {
		report.Score = CalculateRiskScoreWithReputation(report.Results, report.Info)
	} else {
		report.Score = CalculateRiskScore(report.Results)
	}
	report.AuditedAt = time.Now().UTC().Format(time.RFC3339)

	// Sort findings by severity for all formats
	for i := range report.Results {
		sort.Slice(report.Results[i].Findings, func(j, k int) bool {
			return report.Results[i].Findings[j].Severity > report.Results[i].Findings[k].Severity
		})
	}

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
	fmt.Fprintln(r.writer, r.T("project_audit", projectReport.ProjectName))
	fmt.Fprintln(r.writer, r.T("packages_audited", len(projectReport.Reports)))
	fmt.Fprintln(r.writer)

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
		pdf.Cell(0, 10, r.T("project_audit", projectReport.ProjectName))
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

// pdfPageLimit is the maximum number of pages for a single package report.
const pdfPageLimit = 2

// pdfColors holds reusable color constants for PDF rendering.
type pdfColors struct {
	red, gray, dark, green []int
}

var defaultPDFColors = pdfColors{
	red:   []int{215, 58, 73},
	gray:  []int{106, 115, 125},
	dark:  []int{36, 41, 46},
	green: []int{40, 167, 69},
}

func (r *Reporter) addReportToPDF(pdf *fpdf.Fpdf, report Report) {
	pdf.AddPage()
	startPage := pdf.PageNo()
	c := defaultPDFColors

	r.pdfHeader(pdf, report, c)
	r.pdfRiskScore(pdf, report, c)

	allFindings := collectFindings(report.Results)
	if len(allFindings) == 0 {
		pdf.SetFont("Arial", "I", 10)
		pdf.SetTextColor(c.green[0], c.green[1], c.green[2])
		pdf.Cell(0, 10, r.T("no_issues"))
		return
	}

	mergedFindings := mergeSimilarFindings(allFindings)
	r.pdfSeveritySummary(pdf, allFindings, mergedFindings, c)
	r.pdfFindings(pdf, mergedFindings, startPage, c)
}

func (r *Reporter) pdfHeader(pdf *fpdf.Fpdf, report Report, c pdfColors) {
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(c.dark[0], c.dark[1], c.dark[2])
	pdf.Cell(0, 12, r.T("title"))
	pdf.Ln(12)

	pdf.SetFillColor(246, 248, 250)
	pdf.Rect(10, pdf.GetY(), 190, 28, "F")
	pdf.SetFont("Arial", "B", 11)
	pdf.SetY(pdf.GetY() + 3)
	pdf.Cell(95, 6, "  "+fmt.Sprintf("%s: %s@%s", r.T("package"), report.Package, report.Version))
	if report.Info.License != "" {
		pdf.Cell(95, 6, fmt.Sprintf("%s: %s", r.T("license"), report.Info.License))
	}
	pdf.Ln(6)
	pdf.SetFont("Arial", "", 10)
	pdf.Cell(95, 6, "  "+fmt.Sprintf("%s: %d %s", r.T("versions"), report.Info.TotalVersions, r.T("published")))
	pdf.Cell(95, 6, fmt.Sprintf("%s: %d %s", r.T("dependencies"), report.Info.Dependencies, r.T("direct")))
	pdf.Ln(10)
}

func (r *Reporter) pdfRiskScore(pdf *fpdf.Fpdf, report Report, c pdfColors) {
	_, scoreLabel := r.GetRiskLevel(report.Score)
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(50, 6, r.T("risk_assessment")+":")
	pdf.SetFont("Arial", "B", 12)
	if report.Score >= 40 {
		pdf.SetTextColor(c.red[0], c.red[1], c.red[2])
	} else if report.Score >= 20 {
		pdf.SetTextColor(227, 98, 9)
	} else {
		pdf.SetTextColor(c.green[0], c.green[1], c.green[2])
	}
	pdf.Cell(0, 6, fmt.Sprintf("%s (%d/100)", scoreLabel, report.Score))
	pdf.SetTextColor(c.dark[0], c.dark[1], c.dark[2])
	pdf.Ln(10)
}

func (r *Reporter) pdfSeveritySummary(pdf *fpdf.Fpdf, allFindings []analyzer.Finding, mergedFindings []MergedFinding, c pdfColors) {
	severityCounts := countSeverities(allFindings)
	totalOriginal := len(allFindings)
	totalMerged := len(mergedFindings)

	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(0, 6, r.T("findings_summary")+fmt.Sprintf(" (%d %s", totalOriginal, r.T("findings_word")))
	if totalMerged < totalOriginal {
		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(c.gray[0], c.gray[1], c.gray[2])
		pdf.Write(6, fmt.Sprintf(", %d %s", totalMerged, r.T("unique_issues")))
	}
	pdf.Write(6, ")")
	pdf.Ln(6)

	pdf.SetFont("Arial", "", 9)
	summaryParts := []string{}
	if n := severityCounts[analyzer.SeverityCritical]; n > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d CRITICAL", n))
	}
	if n := severityCounts[analyzer.SeverityHigh]; n > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d HIGH", n))
	}
	if n := severityCounts[analyzer.SeverityMedium]; n > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d MEDIUM", n))
	}
	if n := severityCounts[analyzer.SeverityLow]; n > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d LOW", n))
	}
	pdf.SetTextColor(c.gray[0], c.gray[1], c.gray[2])
	pdf.Cell(0, 5, strings.Join(summaryParts, " | "))
	pdf.SetTextColor(c.dark[0], c.dark[1], c.dark[2])
	pdf.Ln(8)
}

func (r *Reporter) pdfFindings(pdf *fpdf.Fpdf, mergedFindings []MergedFinding, startPage int, c pdfColors) {
	displayedCount := 0

	for _, mf := range mergedFindings {
		currentPage := pdf.PageNo()
		if currentPage-startPage >= pdfPageLimit {
			break
		}
		if currentPage-startPage == pdfPageLimit-1 && pdf.GetY() > 240 {
			break
		}

		displayedCount++
		r.pdfRenderFinding(pdf, mf, c)
	}

	if displayedCount < len(mergedFindings) {
		remaining := len(mergedFindings) - displayedCount
		pdf.SetFont("Arial", "I", 9)
		pdf.SetTextColor(c.gray[0], c.gray[1], c.gray[2])
		pdf.Cell(0, 6, fmt.Sprintf("... %s %d %s", r.T("and"), remaining, r.T("more_issues_truncated")))
		pdf.Ln(6)
		pdf.SetFont("Arial", "", 8)
		pdf.Cell(0, 4, r.T("run_terminal_for_full"))
	}
}

func (r *Reporter) pdfRenderFinding(pdf *fpdf.Fpdf, mf MergedFinding, c pdfColors) {
	pdf.SetFont("Arial", "B", 10)
	if mf.Severity >= analyzer.SeverityHigh {
		pdf.SetTextColor(c.red[0], c.red[1], c.red[2])
	} else if mf.Severity >= analyzer.SeverityMedium {
		pdf.SetTextColor(227, 98, 9)
	} else {
		pdf.SetTextColor(c.gray[0], c.gray[1], c.gray[2])
	}

	titleText := fmt.Sprintf("[%s] %s", mf.Severity, r.T(mf.Title))
	if mf.Count > 1 {
		titleText += fmt.Sprintf(" (x%d)", mf.Count)
	}
	pdf.Cell(0, 6, titleText)
	pdf.Ln(5)

	pdf.SetFont("Arial", "I", 8)
	pdf.SetTextColor(c.gray[0], c.gray[1], c.gray[2])
	pdf.Cell(0, 4, r.T("analyzer_label", mf.Analyzer))
	pdf.Ln(4)

	pdf.SetTextColor(c.dark[0], c.dark[1], c.dark[2])
	pdf.SetFont("Arial", "", 9)
	desc := r.T(mf.Description)
	if len(desc) > 200 {
		desc = desc[:197] + "..."
	}
	pdf.MultiCell(0, 4, desc, "", "", false)

	if mf.Count > 1 && len(mf.Instances) > 0 {
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(c.gray[0], c.gray[1], c.gray[2])
		pdf.Cell(0, 4, fmt.Sprintf("+ %d %s", mf.Count-1, r.T("similar_instances")))
		pdf.Ln(4)
	}

	if mf.Remediation != "" {
		pdf.SetFont("Arial", "B", 8)
		pdf.SetTextColor(c.green[0], c.green[1], c.green[2])
		pdf.Cell(15, 4, r.T("remediation")+":")
		pdf.SetFont("Arial", "", 8)
		remediation := r.T(mf.Remediation)
		if len(remediation) > 120 {
			remediation = remediation[:117] + "..."
		}
		pdf.MultiCell(0, 4, remediation, "", "", false)
	}

	pdf.Ln(3)
	pdf.SetDrawColor(234, 236, 239)
	pdf.Line(10, pdf.GetY(), 200, pdf.GetY())
	pdf.Ln(3)
}

// JSONReport extends Report with merged findings for JSON output.
type JSONReport struct {
	Report
	MergedFindings []MergedFinding `json:"merged_findings,omitempty"`
}

func (r *Reporter) renderJSON(report Report) error {
	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")

	// Always include merged findings in JSON output for easier consumption
	allFindings := collectFindings(report.Results)
	merged := mergeSimilarFindings(allFindings)

	jsonReport := JSONReport{
		Report:         report,
		MergedFindings: merged,
	}

	return enc.Encode(jsonReport)
}

func (r *Reporter) renderTerminal(report Report) error {
	w := r.writer

	r.printLogo(w)
	fmt.Fprintln(w)

	allFindings := collectFindings(report.Results)
	severityCounts := countSeverities(allFindings)
	scoreColor, scoreLabel := r.GetRiskLevel(report.Score)

	r.renderExecutiveSummary(w, report, scoreColor, scoreLabel, severityCounts)
	r.renderStatsLine(w, allFindings, severityCounts)
	r.renderTerminalActionChecklist(w, report, allFindings)
	r.renderTerminalPackageInfo(w, report, scoreColor)
	r.renderTerminalErrors(w, report.Results)

	if len(allFindings) == 0 {
		r.printBox(w, " "+r.T("no_issues"), colorGreen)
		fmt.Fprintln(w)
		r.renderTerminalFooter(w, report.AuditedAt)
		return nil
	}

	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Severity > allFindings[j].Severity
	})

	mergedFindings := mergeSimilarFindings(allFindings)
	r.renderFindingsByAction(w, allFindings, mergedFindings)
	r.renderTerminalDetailedFindings(w, allFindings, mergedFindings)
	r.renderQuickReference(w, report)
	r.printSectionHeader(w, r.T("analyzer_breakdown"))
	r.printAnalyzerBreakdown(w, report.Results)
	fmt.Fprintln(w)
	r.renderTerminalFooter(w, report.AuditedAt)

	return nil
}

func countSeverities(findings []analyzer.Finding) map[analyzer.Severity]int {
	counts := map[analyzer.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func (r *Reporter) renderExecutiveSummary(w io.Writer, report Report, scoreColor, scoreLabel string, severityCounts map[analyzer.Severity]int) {
	verdict := r.getVerdict(report.Score, severityCounts)
	fmt.Fprintf(w, "%s%s╔══════════════════════════════════════════════════════════════════════╗%s\n", colorBold, scoreColor, colorReset)
	fmt.Fprintf(w, "%s%s║  %s%-66s  %s║%s\n", colorBold, scoreColor, colorBold, r.T("executive_summary"), scoreColor, colorReset)
	fmt.Fprintf(w, "%s%s╠══════════════════════════════════════════════════════════════════════╣%s\n", colorBold, scoreColor, colorReset)
	fmt.Fprintf(w, "%s%s║%s  %-68s%s║%s\n", colorBold, scoreColor, colorReset, fmt.Sprintf("%s: %s@%s", r.T("package"), report.Package, report.Version), scoreColor, colorReset)
	fmt.Fprintf(w, "%s%s║%s  %-68s%s║%s\n", colorBold, scoreColor, colorReset, fmt.Sprintf("%s: %s (%d/100)", r.T("risk_level"), scoreLabel, report.Score), scoreColor, colorReset)
	fmt.Fprintf(w, "%s%s║%s  %-68s%s║%s\n", colorBold, scoreColor, colorReset, "", scoreColor, colorReset)
	fmt.Fprintf(w, "%s%s║%s  %s%-66s%s  %s║%s\n", colorBold, scoreColor, colorBold, scoreColor, verdict, colorReset, scoreColor, colorReset)
	fmt.Fprintf(w, "%s%s╚══════════════════════════════════════════════════════════════════════╝%s\n", colorBold, scoreColor, colorReset)
	fmt.Fprintln(w)
}

func (r *Reporter) renderStatsLine(w io.Writer, allFindings []analyzer.Finding, severityCounts map[analyzer.Severity]int) {
	if len(allFindings) == 0 {
		return
	}
	stats := []string{}
	if c := severityCounts[analyzer.SeverityCritical]; c > 0 {
		stats = append(stats, fmt.Sprintf("%s%d CRITICAL%s", colorRed, c, colorReset))
	}
	if c := severityCounts[analyzer.SeverityHigh]; c > 0 {
		stats = append(stats, fmt.Sprintf("%s%d HIGH%s", colorRed, c, colorReset))
	}
	if c := severityCounts[analyzer.SeverityMedium]; c > 0 {
		stats = append(stats, fmt.Sprintf("%s%d MEDIUM%s", colorYellow, c, colorReset))
	}
	if c := severityCounts[analyzer.SeverityLow]; c > 0 {
		stats = append(stats, fmt.Sprintf("%s%d LOW%s", colorDim, c, colorReset))
	}
	fmt.Fprintf(w, "  %s: %s\n\n", r.T("findings_detected"), strings.Join(stats, " · "))
}

func (r *Reporter) renderTerminalActionChecklist(w io.Writer, report Report, allFindings []analyzer.Finding) {
	if len(allFindings) == 0 {
		return
	}
	r.printSectionHeader(w, r.T("action_checklist"))
	actions := r.generateActionChecklist(report.Score, allFindings, report.Info.HasScripts)
	for i, action := range actions {
		icon := "□"
		if action.critical {
			icon = fmt.Sprintf("%s⚠%s", colorRed, colorReset)
		}
		fmt.Fprintf(w, "  %s %s%d.%s %s\n", icon, colorBold, i+1, colorReset, action.text)
	}
	fmt.Fprintln(w)
}

func (r *Reporter) renderTerminalPackageInfo(w io.Writer, report Report, scoreColor string) {
	r.printSectionHeader(w, r.T("pkg_info"))
	r.printField(w, r.T("package"), report.Package+"@"+report.Version)
	if report.Info.License != "" {
		r.printField(w, r.T("license"), report.Info.License)
	}
	if len(report.Info.Maintainers) > 0 {
		maintainers := strings.Join(report.Info.Maintainers, ", ")
		if len(maintainers) > 50 {
			maintainers = maintainers[:50] + "..."
		}
		r.printField(w, r.T("maintainers"), maintainers)
	}
	if report.Info.RepoURL != "" {
		r.printField(w, r.T("repository"), report.Info.RepoURL)
	}
	if report.Info.CreatedAt != "" {
		r.printField(w, r.T("created"), report.Info.CreatedAt)
	}
	r.printField(w, r.T("versions"), fmt.Sprintf("%d %s", report.Info.TotalVersions, r.T("published")))
	r.printField(w, r.T("dependencies"), fmt.Sprintf("%d %s", report.Info.Dependencies, r.T("direct")))
	r.renderTerminalScripts(w, report.Info)
	r.renderTerminalReputation(w, report.Info)
	fmt.Fprintln(w)

	r.printSectionHeader(w, r.T("risk_assessment"))
	r.printRiskBar(w, report.Score, scoreColor)
	fmt.Fprintln(w)
}

func (r *Reporter) renderTerminalScripts(w io.Writer, info PackageInfo) {
	if info.HasScripts {
		r.printField(w, r.T("install_scripts"), fmt.Sprintf("%s%s%s", colorRed, r.T("scripts_yes"), colorReset))
	} else {
		r.printField(w, r.T("install_scripts"), fmt.Sprintf("%s%s%s", colorGreen, r.T("scripts_none"), colorReset))
	}
}

func (r *Reporter) renderTerminalReputation(w io.Writer, info PackageInfo) {
	if info.WeeklyDownloads > 0 {
		dlStr := formatDownloads(info.WeeklyDownloads)
		tierColor := colorDim
		switch info.DownloadTier {
		case "massive", "popular":
			tierColor = colorGreen
		case "moderate":
			tierColor = colorCyan
		}
		r.printField(w, r.T("weekly_downloads"), fmt.Sprintf("%s%s/week (%s)%s", tierColor, dlStr, info.DownloadTier, colorReset))
	}
	if info.IsTrustedScope {
		r.printField(w, r.T("trusted_scope"), fmt.Sprintf("%s%s (%s)%s", colorGreen, r.T("yes"), info.TrustedScopeOrg, colorReset))
	}
}

func (r *Reporter) renderTerminalErrors(w io.Writer, results []analyzer.Result) {
	hasErrors := false
	for _, result := range results {
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
}

func (r *Reporter) renderFindingsByAction(w io.Writer, allFindings []analyzer.Finding, mergedFindings []MergedFinding) {
	r.printSectionHeader(w, r.T("findings_by_action"))

	if len(mergedFindings) < len(allFindings) && !r.verbose {
		fmt.Fprintf(w, "  %s%s%s\n", colorDim,
			fmt.Sprintf(r.T("merged_summary"), len(allFindings), len(mergedFindings)), colorReset)
		fmt.Fprintln(w)
	}

	findingsForGrouping := allFindings
	if !r.verbose {
		findingsForGrouping = make([]analyzer.Finding, 0, len(mergedFindings))
		for _, mf := range mergedFindings {
			findingsForGrouping = append(findingsForGrouping, mf.Finding)
		}
	}

	remediationGroups := r.groupByRemediation(findingsForGrouping)
	mergedMap := buildMergedMap(mergedFindings)

	groupOrder := []string{"block_install", "review_scripts", "verify_source", "update_version", "audit_deps", "monitor"}
	for _, groupKey := range groupOrder {
		findings, exists := remediationGroups[groupKey]
		if !exists || len(findings) == 0 {
			continue
		}
		r.renderActionGroup(w, groupKey, findings, mergedMap)
	}
	fmt.Fprintln(w)
}

func buildMergedMap(mergedFindings []MergedFinding) map[string]MergedFinding {
	m := make(map[string]MergedFinding)
	for _, mf := range mergedFindings {
		m[mf.Analyzer+":"+mf.Title] = mf
	}
	return m
}

func (r *Reporter) renderActionGroup(w io.Writer, groupKey string, findings []analyzer.Finding, mergedMap map[string]MergedFinding) {
	groupTitle := r.T("action_group_" + groupKey)
	maxSev := getMaxSeverity(findings)
	sevColor := severityColor(maxSev)

	fmt.Fprintf(w, "\n  %s%s▶ %s%s (%d)\n", colorBold, sevColor, groupTitle, colorReset, len(findings))
	fmt.Fprintf(w, "  %s%s%s\n", colorDim, strings.Repeat("─", reportWidth-4), colorReset)

	for _, f := range findings {
		sc := severityColor(f.Severity)
		title := r.T(f.Title)
		if !r.verbose {
			key := f.Analyzer + ":" + f.Title
			if mf, ok := mergedMap[key]; ok && mf.Count > 1 {
				title += fmt.Sprintf(" %s(x%d)%s", colorDim, mf.Count, colorReset)
			}
		}
		fmt.Fprintf(w, "    %s%s%s %s\n", sc, severityIcon(f.Severity), colorReset, title)
		desc := r.T(f.Description)
		if len(desc) > 60 {
			desc = desc[:60] + "..."
		}
		fmt.Fprintf(w, "      %s%s%s\n", colorDim, desc, colorReset)
	}
}

func (r *Reporter) renderTerminalDetailedFindings(w io.Writer, allFindings []analyzer.Finding, mergedFindings []MergedFinding) {
	r.printSectionHeader(w, r.T("detailed_findings"))
	if r.verbose {
		fmt.Fprintf(w, "  %s%s%s\n\n", colorDim, r.T("detailed_findings_note"), colorReset)
	} else {
		fmt.Fprintf(w, "  %s%s%s\n\n", colorDim, r.T("detailed_findings_merged_note"), colorReset)
	}

	severityOrder := []analyzer.Severity{
		analyzer.SeverityCritical,
		analyzer.SeverityHigh,
		analyzer.SeverityMedium,
		analyzer.SeverityLow,
	}

	for _, sev := range severityOrder {
		r.renderSeveritySection(w, sev, allFindings, mergedFindings)
	}

	if !r.verbose && len(mergedFindings) < len(allFindings) {
		fmt.Fprintf(w, "  %s%s%s\n\n", colorDim, r.T("verbose_hint"), colorReset)
	}
}

func (r *Reporter) renderSeveritySection(w io.Writer, sev analyzer.Severity, allFindings []analyzer.Finding, mergedFindings []MergedFinding) {
	var findingsToDisplay []analyzer.Finding
	var mergedToDisplay []MergedFinding

	if r.verbose {
		findingsToDisplay = filterBySeverity(allFindings, sev)
	} else {
		for _, mf := range mergedFindings {
			if mf.Severity == sev {
				mergedToDisplay = append(mergedToDisplay, mf)
			}
		}
	}

	count := len(findingsToDisplay)
	if !r.verbose {
		count = len(mergedToDisplay)
	}
	if count == 0 {
		return
	}

	sevColor := severityColor(sev)
	label := r.T("findings_count", r.GetSeverityLabel(sev), count)
	fmt.Fprintf(w, "%s%s%s %s %s\n", colorBold, sevColor, severityIcon(sev), label, colorReset)
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", reportWidth), colorReset)

	if r.verbose {
		for i, f := range findingsToDisplay {
			r.printDetailedFinding(w, f, sevColor, sev, 0)
			if i < len(findingsToDisplay)-1 {
				fmt.Fprintf(w, "\n  %s%s%s\n", colorDim, strings.Repeat("·", reportWidth-4), colorReset)
			}
		}
	} else {
		for i, mf := range mergedToDisplay {
			r.printDetailedFinding(w, mf.Finding, sevColor, sev, mf.Count)
			if i < len(mergedToDisplay)-1 {
				fmt.Fprintf(w, "\n  %s%s%s\n", colorDim, strings.Repeat("·", reportWidth-4), colorReset)
			}
		}
	}
	fmt.Fprintf(w, "\n%s%s%s\n\n", colorDim, strings.Repeat("─", reportWidth), colorReset)
}

func (r *Reporter) renderQuickReference(w io.Writer, report Report) {
	r.printSectionHeader(w, r.T("quick_reference"))
	fmt.Fprintf(w, "  %s%s%s\n", colorDim, r.T("quick_ref_intro"), colorReset)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s# %s%s\n", colorDim, r.T("quick_ref_safe_install"), colorReset)
	fmt.Fprintf(w, "  %snpm install --ignore-scripts %s@%s%s\n\n", colorCyan, report.Package, report.Version, colorReset)
	fmt.Fprintf(w, "  %s# %s%s\n", colorDim, r.T("quick_ref_inspect_scripts"), colorReset)
	fmt.Fprintf(w, "  %snpm pack %s@%s && tar -xzf *.tgz && cat package/package.json%s\n\n", colorCyan, report.Package, report.Version, colorReset)
	fmt.Fprintf(w, "  %s# %s%s\n", colorDim, r.T("quick_ref_check_deps"), colorReset)
	fmt.Fprintf(w, "  %snpm ls --all %s%s\n", colorCyan, report.Package, colorReset)
	fmt.Fprintln(w)
}

func (r *Reporter) renderTerminalFooter(w io.Writer, auditedAt string) {
	fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("═", reportWidth), colorReset)
	fmt.Fprintf(w, "%s%s%s\n\n", colorDim, r.T("audited_at", auditedAt), colorReset)
}

// actionItem represents a single action in the checklist.
type actionItem struct {
	text     string
	critical bool
}

// getVerdict returns a human-readable verdict based on the risk score.
func (r *Reporter) getVerdict(score int, counts map[analyzer.Severity]int) string {
	if score >= 70 || counts[analyzer.SeverityCritical] > 0 {
		return r.T("verdict_critical")
	}
	if score >= 40 || counts[analyzer.SeverityHigh] > 0 {
		return r.T("verdict_review")
	}
	if score >= 20 {
		return r.T("verdict_caution")
	}
	return r.T("verdict_safe")
}

// generateActionChecklist creates a prioritized list of actions.
func (r *Reporter) generateActionChecklist(score int, findings []analyzer.Finding, hasScripts bool) []actionItem {
	var actions []actionItem
	seen := make(map[string]bool)

	if score >= 70 {
		actions = append(actions, actionItem{r.T("action_do_not_install"), true})
	}

	for _, f := range findings {
		if item, key := r.findingToAction(f, seen); key != "" {
			actions = append(actions, item)
			seen[key] = true
		}
	}

	if hasScripts && !seen["scripts"] {
		actions = append(actions, actionItem{r.T("action_use_ignore_scripts"), false})
	}

	if len(actions) == 0 {
		actions = append(actions, actionItem{r.T("action_safe_to_install"), false})
	}

	return actions
}

func (r *Reporter) findingToAction(f analyzer.Finding, seen map[string]bool) (actionItem, string) {
	key, actionKey, isCritical := matchActionRule(f)
	if key == "" || seen[key] {
		return actionItem{}, ""
	}
	return actionItem{r.T(actionKey), isCritical}, key
}

func matchActionRule(f analyzer.Finding) (key, actionKey string, isCritical bool) {
	switch f.Analyzer {
	case "install-scripts":
		if f.Severity >= analyzer.SeverityHigh {
			return "scripts", "action_review_scripts", f.Severity >= analyzer.SeverityCritical
		}
	case "typosquatting":
		return "typo", "action_verify_name", true
	case "vulnerabilities":
		return "vuln", "action_check_updates", f.Severity >= analyzer.SeverityCritical
	case "provenance":
		return "prov", "action_verify_provenance", false
	case "maintainers":
		if f.Severity >= analyzer.SeverityMedium {
			return "maint", "action_verify_maintainer", f.Severity >= analyzer.SeverityHigh
		}
	case "dynamic-analysis":
		if f.Severity >= analyzer.SeverityHigh {
			return "dynamic", "action_sandbox_detected", true
		}
	case "proto-pollution":
		if f.Severity >= analyzer.SeverityHigh {
			return "proto", "action_verify_proto", true
		}
	case "behavior-sequence":
		if f.Severity >= analyzer.SeverityHigh {
			return "behavior", "action_verify_behavior", true
		}
	case "multistage-loader":
		if f.Severity >= analyzer.SeverityHigh {
			return "loader", "action_verify_loader", true
		}
	}
	return "", "", false
}

// groupByRemediation groups findings by their remediation action.
func (r *Reporter) groupByRemediation(findings []analyzer.Finding) map[string][]analyzer.Finding {
	groups := make(map[string][]analyzer.Finding)

	for _, f := range findings {
		var group string
		switch {
		case f.Severity == analyzer.SeverityCritical && (f.Analyzer == "typosquatting" || f.Analyzer == "dynamic-analysis"):
			group = "block_install"
		case f.Analyzer == "install-scripts" || strings.Contains(f.Title, "script"):
			group = "review_scripts"
		case f.Analyzer == "provenance" || f.Analyzer == "maintainers" || f.Analyzer == "typosquatting":
			group = "verify_source"
		case f.Analyzer == "vulnerabilities":
			group = "update_version"
		case f.Analyzer == "dependencies" || f.Analyzer == "lockfile":
			group = "audit_deps"
		default:
			group = "monitor"
		}
		groups[group] = append(groups[group], f)
	}

	return groups
}

// getMaxSeverity returns the highest severity in a slice of findings.
func getMaxSeverity(findings []analyzer.Finding) analyzer.Severity {
	max := analyzer.SeverityLow
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

func (r *Reporter) printLogo(w io.Writer) {
	logo := `
    ___             _ _ _   _
   / _ \           | (_) | | |
  / /_\ \_   _  __| |_| |_| |_ ___ _ __
  |  _  | | | |/ _` + "`" + ` | | __| __/ _ \ '__|
  | | | | |_| | (_| | | |_| ||  __/ |
  \_| |_/\__,_|\__,_|_|\__|\__\___|_|
`
	fmt.Fprintf(w, "%s%s%s\n", colorBold, colorMagenta, logo)
	fmt.Fprintf(w, " %s%s npm Security Audit - Version 1.7.0 %s\n", colorCyan, strings.Repeat("━", 10), colorReset)
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
	fmt.Fprintf(w, "### %s (%d/100)\n\n", scoreLabel, report.Score)

	allFindings := collectFindings(report.Results)
	if len(allFindings) == 0 {
		fmt.Fprintf(w, "> %s\n\n", r.T("no_issues"))
	} else {
		fmt.Fprintf(w, "## %s\n\n", r.T("findings_summary"))

		for _, f := range allFindings {
			severityEmoji := "🛡️"
			switch f.Severity {
			case analyzer.SeverityCritical:
				severityEmoji = "🛑"
			case analyzer.SeverityHigh:
				severityEmoji = "⚠️"
			case analyzer.SeverityMedium:
				severityEmoji = "🔸"
			case analyzer.SeverityLow:
				severityEmoji = "🔹"
			}

			fmt.Fprintf(w, "### %s [%s] %s\n\n", severityEmoji, f.Severity, r.T(f.Title))
			fmt.Fprintf(w, "- **%s**: %s\n", r.T("analyzer_label", ""), f.Analyzer)
			fmt.Fprintf(w, "\n%s\n\n", r.T(f.Description))

			if f.ExploitExample != "" {
				fmt.Fprintf(w, "#### 💣 %s\n\n```javascript\n%s\n```\n\n", r.T("attack_scenario"), r.T(f.ExploitExample))
			}

			if f.Remediation != "" {
				fmt.Fprintf(w, "#### ✅ %s\n\n> %s\n\n", r.T("remediation"), r.T(f.Remediation))
			}
			fmt.Fprintf(w, "---\n\n")
		}
	}

	fmt.Fprintf(w, "*%s*\n", r.T("audited_at", report.AuditedAt))
	return nil
}

func (r *Reporter) renderHTML(report Report) error {
	w := r.writer
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>%s - %s</title>
<style>
	body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; line-height: 1.6; color: #24292e; max-width: 900px; margin: 0 auto; padding: 2rem; background: #f6f8fa; }
	.card { background: white; border: 1px solid #e1e4e8; border-radius: 6px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(27,31,35,0.12); }
	h1, h2, h3 { border-bottom: 1px solid #eaecef; padding-bottom: .3em; }
	.score-high { color: #d73a49; } .score-med { color: #e36209; } .score-low { color: #28a745; }
	.finding { border-left: 5px solid #e1e4e8; padding-left: 1rem; margin-bottom: 2rem; }
	.CRITICAL { border-color: #cb2431; background: #fff5f5; }
	.HIGH { border-color: #d73a49; background: #fff5f5; }
	.MEDIUM { border-color: #e36209; background: #fffdef; }
	.LOW { border-color: #28a745; background: #f0fff4; }
	pre { background: #2f363d; color: #fafbfc; padding: 1rem; border-radius: 6px; overflow-x: auto; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
	code { font-family: inherit; }
	.remediation { background: #e1f5fe; padding: 1rem; border-radius: 6px; border-left: 5px solid #03a9f4; }
	.footer { text-align: center; color: #6a737d; font-size: 0.8rem; margin-top: 4rem; }
</style>
</head>
<body>`, r.T("title"), report.Package)

	fmt.Fprintf(w, "<h1>%s</h1>", r.T("title"))

	fmt.Fprintf(w, "<div class='card'><h2>%s</h2><ul>", r.T("pkg_info"))
	fmt.Fprintf(w, "<li><b>%s</b>: %s@%s</li>", r.T("package"), report.Package, report.Version)
	if report.Info.License != "" {
		fmt.Fprintf(w, "<li><b>%s</b>: %s</li>", r.T("license"), report.Info.License)
	}
	fmt.Fprintf(w, "<li><b>%s</b>: %d</li>", r.T("versions"), report.Info.TotalVersions)
	fmt.Fprintf(w, "</ul></div>")

	_, scoreLabel := r.GetRiskLevel(report.Score)
	fmt.Fprintf(w, "<div class='card'><h2>%s</h2><h3 class='score-high'>%s (%d/100)</h3></div>", r.T("risk_assessment"), scoreLabel, report.Score)

	allFindings := collectFindings(report.Results)
	if len(allFindings) > 0 {
		fmt.Fprintf(w, "<h2>%s</h2>", r.T("findings_summary"))
		for _, f := range allFindings {
			fmt.Fprintf(w, "<div class='card finding %s'>", f.Severity)
			fmt.Fprintf(w, "<h3>[%s] %s</h3>", f.Severity, r.T(f.Title))
			fmt.Fprintf(w, "<p><i>%s: %s</i></p>", r.T("analyzer_label", ""), f.Analyzer)
			fmt.Fprintf(w, "<p>%s</p>", r.T(f.Description))

			if f.ExploitExample != "" {
				fmt.Fprintf(w, "<h4>💣 %s</h4><pre><code>%s</code></pre>", r.T("attack_scenario"), r.T(f.ExploitExample))
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "<div class='remediation'><h4>✅ %s</h4><p>%s</p></div>", r.T("remediation"), r.T(f.Remediation))
			}
			fmt.Fprintf(w, "</div>")
		}
	} else {
		fmt.Fprintf(w, "<div class='card'><p>%s</p></div>", r.T("no_issues"))
	}

	fmt.Fprintf(w, "<div class='footer'>%s</div></body></html>", r.T("audited_at", report.AuditedAt))
	return nil
}

func (r *Reporter) renderCSV(report Report) error {
	w := r.writer
	allFindings := collectFindings(report.Results)
	fmt.Fprintf(w, "%s,%s,%s,%s\n", r.T("csv_severity"), r.T("csv_analyzer"), r.T("csv_title"), r.T("csv_description"))
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

// printDetailedFinding prints a single finding with full details.
// If count > 1, it indicates this is a merged finding with multiple occurrences.
func (r *Reporter) printDetailedFinding(w io.Writer, f analyzer.Finding, sevColor string, sev analyzer.Severity, count int) {
	title := r.T(f.Title)
	if count > 1 {
		title += fmt.Sprintf(" %s(x%d occurrences)%s", colorDim, count, colorReset)
	}
	fmt.Fprintf(w, "\n  %s%s%s %s%s\n",
		colorBold, sevColor, severityIcon(sev), title, colorReset)
	fmt.Fprintf(w, "  %s%s%s\n", colorDim, r.T("analyzer_label", f.Analyzer), colorReset)
	r.printWrapped(w, r.T(f.Description), "  ", reportWidth)

	if f.ExploitExample != "" {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s%s%s%s\n", colorBold, colorMagenta, r.T("attack_scenario"), colorReset)
		lines := strings.Split(r.T(f.ExploitExample), "\n")
		maxL := 0
		for _, l := range lines {
			if len(l) > maxL {
				maxL = len(l)
			}
		}
		if maxL > reportWidth-8 {
			maxL = reportWidth - 8
		}

		fmt.Fprintf(w, "  %s%s  ┌%s┐%s\n", colorMagenta, colorDim, strings.Repeat("─", maxL+2), colorReset)
		for _, line := range lines {
			if len(line) > maxL {
				line = line[:maxL]
			}
			padding := strings.Repeat(" ", maxL-len(line))
			fmt.Fprintf(w, "  %s%s  │ %s%s%s │%s\n", colorMagenta, colorDim, colorReset, line, padding, colorReset)
		}
		fmt.Fprintf(w, "  %s%s  └%s┘%s\n", colorMagenta, colorDim, strings.Repeat("─", maxL+2), colorReset)
	}

	if f.Remediation != "" {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s%s%s%s\n", colorBold, colorGreen, r.T("remediation"), colorReset)
		r.printWrapped(w, r.T(f.Remediation), "  ", reportWidth)
	}
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

type breakdownEntry struct {
	name     string
	total    int
	critical int
	high     int
	medium   int
	low      int
}

func buildBreakdownEntries(results []analyzer.Result) []breakdownEntry {
	var entries []breakdownEntry
	for _, res := range results {
		e := breakdownEntry{name: res.AnalyzerName}
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
	return entries
}

func (r *Reporter) printAnalyzerBreakdown(w io.Writer, results []analyzer.Result) {
	entries := buildBreakdownEntries(results)

	maxFindings := 0
	for _, e := range entries {
		if e.total > maxFindings {
			maxFindings = e.total
		}
	}

	for _, e := range entries {
		r.printBreakdownEntry(w, e, maxFindings)
	}
}

func (r *Reporter) printBreakdownEntry(w io.Writer, e breakdownEntry, maxFindings int) {
	const maxBar = 30
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

	fmt.Fprintf(w, "  %-18s %s%-30s%s %d", e.name, breakdownColor(e), bar, colorReset, e.total)
	if e.total > 0 {
		parts := []string{}
		if e.critical > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", e.critical, r.T("severity_critical_short")))
		}
		if e.high > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", e.high, r.T("severity_high_short")))
		}
		if e.medium > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", e.medium, r.T("severity_medium_short")))
		}
		if e.low > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", e.low, r.T("severity_low_short")))
		}
		fmt.Fprintf(w, " (%s)", strings.Join(parts, " "))
	} else {
		fmt.Fprintf(w, " %s✓ %s%s", colorGreen, r.T("clean"), colorReset)
	}
	fmt.Fprintln(w)
}

// ── Pure Functions ──

// formatDownloads returns a human-readable download count.
func formatDownloads(downloads int) string {
	switch {
	case downloads >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(downloads)/1_000_000_000)
	case downloads >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(downloads)/1_000_000)
	case downloads >= 1_000:
		return fmt.Sprintf("%.1fK", float64(downloads)/1_000)
	default:
		return fmt.Sprintf("%d", downloads)
	}
}

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

func breakdownColor(e breakdownEntry) string {
	if e.critical > 0 || e.high > 0 {
		return colorRed
	}
	if e.medium > 0 {
		return colorYellow
	}
	return colorDim
}

func (r *Reporter) pluralize(count int) string {
	if count == 1 {
		return r.T("finding_plural")
	}
	return r.T("findings_plural")
}

func collectFindings(results []analyzer.Result) []analyzer.Finding {
	var all []analyzer.Finding
	for _, r := range results {
		all = append(all, r.Findings...)
	}
	return all
}

// MergedFinding represents multiple similar findings combined into one.
type MergedFinding struct {
	analyzer.Finding
	Count     int      // Number of findings merged
	Instances []string // Brief descriptions of each instance (for context)
}

// mergeSimilarFindings combines findings with the same analyzer and title.
// It keeps the highest severity and aggregates instance details.
func mergeSimilarFindings(findings []analyzer.Finding) []MergedFinding {
	type mergeKey struct {
		analyzer string
		title    string
	}

	groups := make(map[mergeKey]*MergedFinding)
	order := []mergeKey{} // Preserve order of first occurrence

	for _, f := range findings {
		key := mergeKey{analyzer: f.Analyzer, title: f.Title}

		if existing, ok := groups[key]; ok {
			// Merge: keep highest severity
			if f.Severity > existing.Severity {
				existing.Severity = f.Severity
			}
			// Accumulate instances (truncated descriptions as context)
			if f.Description != existing.Description {
				instance := f.Description
				if len(instance) > 80 {
					instance = instance[:80] + "..."
				}
				existing.Instances = append(existing.Instances, instance)
			}
			existing.Count++
			// Prefer non-empty exploit examples and remediations
			if existing.ExploitExample == "" && f.ExploitExample != "" {
				existing.ExploitExample = f.ExploitExample
			}
			if existing.Remediation == "" && f.Remediation != "" {
				existing.Remediation = f.Remediation
			}
		} else {
			mf := &MergedFinding{
				Finding:   f,
				Count:     1,
				Instances: []string{},
			}
			groups[key] = mf
			order = append(order, key)
		}
	}

	// Collect in original order, sorted by severity (highest first)
	result := make([]MergedFinding, 0, len(groups))
	for _, key := range order {
		result = append(result, *groups[key])
	}

	// Sort by severity descending, then by count descending
	sort.Slice(result, func(i, j int) bool {
		if result[i].Severity != result[j].Severity {
			return result[i].Severity > result[j].Severity
		}
		return result[i].Count > result[j].Count
	})

	return result
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

// CalculateRiskScoreWithReputation computes a risk score adjusted by package reputation.
// Trusted scopes and high download counts reduce the score.
func CalculateRiskScoreWithReputation(results []analyzer.Result, info PackageInfo) int {
	baseScore := CalculateRiskScore(results)

	// Apply reputation adjustments
	adjustment := 0

	// Trusted scope: significant reduction
	if info.IsTrustedScope {
		adjustment -= 20
	}

	// Download tier adjustments - larger reductions for widely-used packages
	switch info.DownloadTier {
	case "massive": // 10M+ downloads - extremely well-vetted
		adjustment -= 25
	case "popular": // 1M+ downloads - very well-vetted
		adjustment -= 15
	case "moderate": // 100K+ downloads
		adjustment -= 5
	case "minimal": // <10K downloads with many findings is suspicious
		// No bonus, but could add penalty in future
	}

	score := baseScore + adjustment
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}
