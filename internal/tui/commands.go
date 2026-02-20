package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/audit"
	"github.com/kluth/npm-security-auditter/internal/intelligence"
	"github.com/kluth/npm-security-auditter/internal/reporter"
)

func convertFindings(afs []analyzer.Finding) []Finding {
	out := make([]Finding, len(afs))
	for i, f := range afs {
		out[i] = Finding{
			Analyzer:       f.Analyzer,
			Severity:       f.Severity.String(),
			FindingTitle:   f.Title,
			Detail:         f.Description,
			File:           f.File,
			Line:           f.Line,
			Column:         f.Column,
			CodeExtract:    f.CodeExtract,
			ExploitExample: f.ExploitExample,
			Remediation:    f.Remediation,
		}
	}
	return out
}

func resultFromReport(pr reporter.ProjectReport, duration time.Duration) *AuditResult {
	var allFindings []analyzer.Finding
	scoreSum := 0.0
	count := 0

	for _, r := range pr.Reports {
		for _, res := range r.Results {
			for _, f := range res.Findings {
				// Prepend package name for context in list
				f.Title = fmt.Sprintf("[%s] %s", r.Package, f.Title)
				allFindings = append(allFindings, f)
			}
		}
		scoreSum += float64(r.Score)
		count++
	}

	avgScore := 0.0
	if count > 0 {
		avgScore = scoreSum / float64(count)
	}

	// For single package, use its score directly
	if len(pr.Reports) == 1 {
		avgScore = float64(pr.Reports[0].Score)
		// Fix title redundancy for single package if desired, but [pkg] prefix is okay
	}

	return &AuditResult{
		PackageName: pr.ProjectName,
		RiskScore:   avgScore,
		Findings:    convertFindings(allFindings),
		RawFindings: allFindings,
		Duration:    duration,
	}
}

func runPackageAudit(nameVersion string, cfg SettingsConfig) tea.Msg {
	start := time.Now()
	
	timeout, _ := strconv.Atoi(cfg.Timeout)
	sev, _ := parseSeverity(cfg.Severity)
	
	auditCfg := audit.Config{
		RegistryURL: cfg.Registry,
		Timeout:     timeout,
		MinSeverity: sev,
		NoSandbox:   false, // TUI default
	}
	runner := audit.NewRunner(auditCfg)

	ctx := context.Background()
	report, err := runner.Run(ctx, nameVersion)
	if err != nil {
		return auditErrorMsg{err: err}
	}

	return auditCompleteMsg{result: resultFromReport(report, time.Since(start))}
}

func runProjectAudit(path string, cfg SettingsConfig) tea.Msg {
	start := time.Now()
	
	timeout, _ := strconv.Atoi(cfg.Timeout)
	sev, _ := parseSeverity(cfg.Severity)
	
	auditCfg := audit.Config{
		RegistryURL: cfg.Registry,
		Timeout:     timeout,
		MinSeverity: sev,
		ProjectPath: path,
	}
	runner := audit.NewRunner(auditCfg)

	ctx := context.Background()
	report, err := runner.Run(ctx, path)
	if err != nil {
		return auditErrorMsg{err: err}
	}

	return auditCompleteMsg{result: resultFromReport(report, time.Since(start))}
}

func runNodeModulesAudit(path string, cfg SettingsConfig) tea.Msg {
	start := time.Now()
	
	timeout, _ := strconv.Atoi(cfg.Timeout)
	sev, _ := parseSeverity(cfg.Severity)
	
	auditCfg := audit.Config{
		RegistryURL:      cfg.Registry,
		Timeout:          timeout,
		MinSeverity:      sev,
		AuditNodeModules: true,
	}
	runner := audit.NewRunner(auditCfg)

	ctx := context.Background()
	report, err := runner.Run(ctx, path) // path is likely "." or dir containing node_modules
	if err != nil {
		return auditErrorMsg{err: err}
	}

	return auditCompleteMsg{result: resultFromReport(report, time.Since(start))}
}

func runThreatUpdate(sourceURL string) tea.Msg {
	ctx := context.Background()
	m := intelligence.NewManager("")
	// In a real scenario we'd add the custom provider
	// m.AddProvider(intelligence.NewCustomProvider(sourceURL))
	if err := m.Update(ctx); err != nil {
		return threatErrorMsg{err: err}
	}
	return threatUpdateMsg{msg: "Threat intelligence updated successfully"}
}

func saveReport(result *AuditResult, path string) tea.Msg {
	if result == nil {
		return reportSaveErrorMsg{err: fmt.Errorf("no results to save")}
	}

	f, err := os.Create(path)
	if err != nil {
		return reportSaveErrorMsg{err: fmt.Errorf("creating file %s: %w", path, err)}
	}
	defer f.Close()

	// Determine format from extension
	format := reporter.FormatJSON
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		format = reporter.FormatJSON
	case ".md":
		format = reporter.FormatMarkdown
	case ".html":
		format = reporter.FormatHTML
	case ".csv":
		format = reporter.FormatCSV
	case ".pdf":
		format = reporter.FormatPDF
	case ".sarif":
		format = reporter.FormatSARIF
	case ".txt":
		format = reporter.FormatTerminal
	}

	// Create a reporter.Report from AuditResult
	rep := reporter.Report{
		Package: result.PackageName,
		Version: "audited", // TUI result is already aggregated
		Results: []analyzer.Result{
			{
				AnalyzerName: "TUI Aggregate",
				Findings:     result.RawFindings,
			},
		},
		Score: int(result.RiskScore),
		Info: reporter.PackageInfo{
			TotalVersions: 1,
			Dependencies:  0,
		},
		AuditedAt: time.Now().Format(time.RFC3339),
	}

	r := reporter.New(f, format, reporter.LangEN)
	if err := r.Render(rep); err != nil {
		return reportSaveErrorMsg{err: fmt.Errorf("rendering report: %w", err)}
	}

	return reportSavedMsg{path: path}
}

func runAuditTopRepos(category string, cfg SettingsConfig) tea.Msg {
	start := time.Now()
	
	timeout, _ := strconv.Atoi(cfg.Timeout)
	sev, _ := parseSeverity(cfg.Severity)
	
	// Fetch top repos first
	ctx := context.Background()
	deps, err := intelligence.FetchTopReposByCategory(ctx, category, 10)
	if err != nil {
		return auditErrorMsg{err: fmt.Errorf("fetching top repos: %w", err)}
	}
	
	auditCfg := audit.Config{
		RegistryURL: cfg.Registry,
		Timeout:     timeout,
		MinSeverity: sev,
	}
	runner := audit.NewRunner(auditCfg)
	
	report, err := runner.RunBatch(ctx, deps)
	if err != nil {
		return auditErrorMsg{err: err}
	}
	report.ProjectName = "Top Repos: " + category

	return auditCompleteMsg{result: resultFromReport(report, time.Since(start))}
}

func parseSeverity(s string) (analyzer.Severity, error) {
	switch strings.ToLower(s) {
	case "low":
		return analyzer.SeverityLow, nil
	case "medium":
		return analyzer.SeverityMedium, nil
	case "high":
		return analyzer.SeverityHigh, nil
	case "critical":
		return analyzer.SeverityCritical, nil
	default:
		return analyzer.SeverityLow, nil
	}
}
