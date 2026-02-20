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
	"github.com/kluth/npm-security-auditter/internal/intelligence"
	"github.com/kluth/npm-security-auditter/internal/project"
	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/reporter"
	"github.com/kluth/npm-security-auditter/internal/reputation"
)

func buildClient(cfg SettingsConfig) *registry.Client {
	// Registry client now takes only URL
	return registry.NewClient(cfg.Registry)
}

func buildAnalyzers(client *registry.Client) []analyzer.Analyzer {
	intelMgr := intelligence.NewManager("")
	intelMgr.Load()

	// Reconstruct the default analyzers list
	analyzers := []analyzer.Analyzer{
		analyzer.NewVulnAnalyzer(),
		analyzer.NewIntelAnalyzer(intelMgr),
		analyzer.NewScriptsAnalyzer(),
		analyzer.NewTyposquatAnalyzer(),
		analyzer.NewSlopsquattingAnalyzer(),
		analyzer.NewMaintainerAnalyzer(),
		analyzer.NewMetadataAnalyzer(),
		analyzer.NewDepsAnalyzer(),
		analyzer.NewRemoteDepsAnalyzer(),
		analyzer.NewBinaryAnalyzer(),
		analyzer.NewProvenanceAnalyzer(),
		analyzer.NewTarballAnalyzer(),
		analyzer.NewRepoVerifierAnalyzer(),
		analyzer.NewIssuesAnalyzer(),
		analyzer.NewShellScriptAnalyzer(),
		analyzer.NewScorecardAnalyzer(),
		analyzer.NewCommitHistoryAnalyzer(),
		analyzer.NewDownloadAnalyzer(),
		analyzer.NewManifestConfusionAnalyzer(),
		analyzer.NewVersionAnomalyAnalyzer(),
		analyzer.NewStarjackingAnalyzer(),
		analyzer.NewCommunityTrustAnalyzer(),
		analyzer.NewReproducibleBuildAnalyzer(),
		analyzer.NewCodeSigningAnalyzer(),
		analyzer.NewSandboxAnalyzer(),
	}
	return analyzers
}

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

func runPackageAudit(nameVersion string, cfg SettingsConfig) tea.Msg {
	start := time.Now()
	client := buildClient(cfg)

	// Parse name@version
	name := nameVersion
	version := "latest"
	if idx := strings.LastIndex(nameVersion, "@"); idx > 0 {
		name = nameVersion[:idx]
		version = nameVersion[idx+1:]
	}

	timeout := 30
	if v, err := strconv.Atoi(cfg.Timeout); err == nil && v > 0 {
		timeout = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	meta, err := client.GetPackage(ctx, name)
	if err != nil {
		return auditErrorMsg{err: fmt.Errorf("fetching metadata for %s: %w", name, err)}
	}

	ver, ok := meta.Versions[version]
	if !ok {
		// Try "latest" tag
		if version == "latest" {
			if tag, exists := meta.DistTags["latest"]; exists {
				ver, ok = meta.Versions[tag]
			}
		}
		if !ok {
			return auditErrorMsg{err: fmt.Errorf("version %s not found for %s", version, name)}
		}
	}

	analyzers := buildAnalyzers(client)
	// RunAll returns []analyzer.Result
	results := analyzer.RunAll(ctx, analyzers, meta, &ver)

	var allFindings []analyzer.Finding
	for _, res := range results {
		allFindings = append(allFindings, res.Findings...)
	}

	// Filter by severity if configured
	minSev, _ := parseSeverity(cfg.Severity)
	allFindings = analyzer.FilterByMinSeverity(allFindings, minSev)

	// Calculate score using improved reporter logic
	repInfo := reporter.PackageInfo{
		License:         ver.License,
		TotalVersions:   len(meta.Versions),
		Dependencies:    len(ver.Dependencies),
	}
	
	isTrusted, _ := reputation.IsTrustedScope(name)
	downloads, _ := client.GetDownloads(ctx, name)
	
	if downloads != nil {
		repInfo.WeeklyDownloads = downloads.Downloads
		repInfo.DownloadTier = string(reputation.GetDownloadTier(downloads.Downloads))
		repInfo.ReputationScore = reputation.CalculateReputationScore(name, downloads.Downloads)
	} else {
		repInfo.ReputationScore = 50 // default
	}
	
	repInfo.IsTrustedScope = isTrusted

	score := reporter.CalculateRiskScoreWithReputation(results, repInfo)

	return auditCompleteMsg{result: &AuditResult{
		PackageName: nameVersion,
		RiskScore:   float64(score),
		Findings:    convertFindings(allFindings),
		RawFindings: allFindings,
		Duration:    time.Since(start),
	}}
}

func runProjectAudit(path string, cfg SettingsConfig) tea.Msg {
	start := time.Now()
	client := buildClient(cfg)
	
	timeout := 30
	if v, err := strconv.Atoi(cfg.Timeout); err == nil && v > 0 {
		timeout = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second*10) // More time for projects
	defer cancel()

	var deps []project.Dependency
	var err error
	if strings.HasSuffix(path, "package-lock.json") {
		deps, err = project.ParsePackageLock(path)
	} else if strings.HasSuffix(path, "package.json") {
		deps, err = project.ParsePackageJSON(path)
	} else {
		// Try appending package.json
		deps, err = project.ParsePackageJSON(path + "/package.json")
	}

	if err != nil {
		return auditErrorMsg{err: fmt.Errorf("parsing project at %s: %w", path, err)}
	}

	analyzers := buildAnalyzers(client)
	var allFindings []analyzer.Finding

	// Limit concurrency? For TUI simplicity, run sequential or batch
	for _, dep := range deps {
		meta, mErr := client.GetPackage(ctx, dep.Name)
		if mErr != nil {
			continue
		}
		
		verTag := dep.Version
		if verTag == "" || strings.HasPrefix(verTag, "^") || strings.HasPrefix(verTag, "~") {
			if tag, ok := meta.DistTags["latest"]; ok {
				verTag = tag
			}
		}

		ver, ok := meta.Versions[verTag]
		if !ok {
			continue
		}
		
		results := analyzer.RunAll(ctx, analyzers, meta, &ver)
		for _, res := range results {
			// Prepend package name to finding title for project context
			for _, f := range res.Findings {
				f.Title = fmt.Sprintf("%s: %s", dep.Name, f.Title)
				allFindings = append(allFindings, f)
			}
		}
	}

	minSev, _ := parseSeverity(cfg.Severity)
	allFindings = analyzer.FilterByMinSeverity(allFindings, minSev)

	// Simple score aggregation
	score := 0
	for _, f := range allFindings {
		if f.Severity == analyzer.SeverityCritical { score += 5 } // lower per-finding weight for projects
		if f.Severity == analyzer.SeverityHigh { score += 2 }
	}
	if score > 100 { score = 100 }

	return auditCompleteMsg{result: &AuditResult{
		PackageName: path,
		RiskScore:   float64(score),
		Findings:    convertFindings(allFindings),
		RawFindings: allFindings,
		Duration:    time.Since(start),
	}}
}

func runNodeModulesAudit(path string, cfg SettingsConfig) tea.Msg {
	start := time.Now()
	client := buildClient(cfg)
	ctx := context.Background() // TODO: timeout

	deps, err := project.AuditNodeModules(path)
	if err != nil {
		return auditErrorMsg{err: fmt.Errorf("scanning node_modules at %s: %w", path, err)}
	}

	analyzers := buildAnalyzers(client)
	var allFindings []analyzer.Finding

	for _, dep := range deps {
		meta, mErr := client.GetPackage(ctx, dep.Name)
		if mErr != nil {
			continue
		}
		// Best effort version matching not implemented fully for node_modules scan yet in this snippet
		// Assuming latest for scan analysis if version unknown
		tag := "latest"
		if t, ok := meta.DistTags["latest"]; ok {
			tag = t
		}
		ver, ok := meta.Versions[tag]
		if !ok {
			continue
		}
		
		results := analyzer.RunAll(ctx, analyzers, meta, &ver)
		for _, res := range results {
			for _, f := range res.Findings {
				f.Title = fmt.Sprintf("%s: %s", dep.Name, f.Title)
				allFindings = append(allFindings, f)
			}
		}
	}
	
	minSev, _ := parseSeverity(cfg.Severity)
	allFindings = analyzer.FilterByMinSeverity(allFindings, minSev)

	score := 0
	if len(allFindings) > 0 { score = 50 } // Arbitrary for now

	return auditCompleteMsg{result: &AuditResult{
		PackageName: "node_modules: " + path,
		RiskScore:   float64(score),
		Findings:    convertFindings(allFindings),
		RawFindings: allFindings,
		Duration:    time.Since(start),
	}}
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
	client := buildClient(cfg)
	ctx := context.Background()

	deps, err := intelligence.FetchTopReposByCategory(ctx, category, 10)
	if err != nil {
		return auditErrorMsg{err: fmt.Errorf("fetching top repos for %s: %w", category, err)}
	}

	analyzers := buildAnalyzers(client)
	var allFindings []analyzer.Finding

	for _, dep := range deps {
		meta, mErr := client.GetPackage(ctx, dep.Name)
		if mErr != nil {
			continue
		}
		// Use latest for top repos
		tag, exists := meta.DistTags["latest"]
		if !exists {
			continue
		}
		ver, ok := meta.Versions[tag]
		if !ok {
			continue
		}

		results := analyzer.RunAll(ctx, analyzers, meta, &ver)
		for _, res := range results {
			// Prepend package name to finding title
			for _, f := range res.Findings {
				f.Title = fmt.Sprintf("%s: %s", dep.Name, f.Title)
				allFindings = append(allFindings, f)
			}
		}
	}

	minSev, _ := parseSeverity(cfg.Severity)
	allFindings = analyzer.FilterByMinSeverity(allFindings, minSev)

	score := 0
	if len(allFindings) > 0 {
		score = 50
	}

	return auditCompleteMsg{result: &AuditResult{
		PackageName: "Top Repos: " + category,
		RiskScore:   float64(score),
		Findings:    convertFindings(allFindings),
		RawFindings: allFindings,
		Duration:    time.Since(start),
	}}
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
