package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kluth/npm-security-auditter/internal/ai"
	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/project"
	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/reporter"
	"github.com/kluth/npm-security-auditter/internal/reputation"
	"github.com/spf13/cobra"
)

var (
	registryURL      string
	jsonOutput       bool
	format           string
	lang             string
	minSeverity      string
	interactive      bool
	projectPath      string
	auditNodeModules bool
	outputFile       string
	timeout          int
	concurrency      int
	noSandbox        bool
	verbose          bool
	aiSummary        bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "auditter <package-name>",
		Short: "Audit npm packages for security risks",
		Long: `auditter performs a comprehensive security audit of npm packages.
		
		It checks for known vulnerabilities, suspicious install scripts,
		typosquatting, maintainer risks, metadata anomalies, dependency
		issues, binary/obfuscated code, supply chain provenance,
		tarball contents, repository verification, and behavior in a sandbox environment.
		
		Examples:  auditter lodash
  auditter express --json --output report.json
  auditter --project package.json --severity high
  auditter --node-modules --format html --output audit.html`,
		Version: "2.1.0",
		RunE:    run,
	}

	rootCmd.Flags().StringVarP(&registryURL, "registry", "r", "", "npm registry URL (default: https://registry.npmjs.org)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "output results as JSON (alias for --format json)")
	rootCmd.Flags().StringVar(&format, "format", "terminal", "output format (terminal, json, markdown, html, csv, pdf)")
	rootCmd.Flags().StringVar(&lang, "lang", "en", "language for the report (en, de, fr, es, it, pt, jp, zh, ru, tlh, vul, sin)")
	rootCmd.Flags().StringVarP(&minSeverity, "severity", "s", "", "minimum severity to report (low, medium, high, critical)")
	rootCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "run in interactive TUI mode")
	rootCmd.Flags().StringVarP(&projectPath, "project", "p", "", "path to package.json or package-lock.json to audit a full project")
	rootCmd.Flags().BoolVar(&auditNodeModules, "node-modules", false, "audit dependencies from node_modules directory")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "write report to file instead of stdout")
	rootCmd.Flags().IntVar(&timeout, "timeout", 180, "timeout in seconds for each package audit")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 5, "max number of concurrent package audits")
	rootCmd.Flags().BoolVar(&noSandbox, "no-sandbox", false, "disable dynamic analysis in sandbox")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output (show all individual findings)")
	rootCmd.Flags().BoolVar(&aiSummary, "ai-summary", false, "generate AI analysis via Gemini CLI")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	if interactive {
		p := tea.NewProgram(initialModel())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("error running TUI: %w", err)
		}
		return nil
	}

	deps, err := resolveDependencies(args)
	if err != nil {
		return err
	}

	if jsonOutput {
		format = "json"
	}

	sev, err := resolveMinSeverity()
	if err != nil {
		return err
	}

	out, cleanup, err := resolveOutput()
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	rep := reporter.NewWithOptions(out, format, reporter.Language(lang), verbose)
	projectReport := buildProjectReport(deps, sev, registry.NewClient(registryURL), buildAnalyzers())

	renderErr := renderReport(rep, projectReport, deps)
	if renderErr != nil {
		return renderErr
	}

	if aiSummary && len(projectReport.Reports) > 0 {
		renderAISummary(out, projectReport, deps)
	}

	return nil
}

func resolveDependencies(args []string) ([]project.Dependency, error) {
	if projectPath != "" {
		if strings.HasSuffix(projectPath, "package-lock.json") {
			deps, err := project.ParsePackageLock(projectPath)
			if err != nil {
				return nil, fmt.Errorf("failed to parse project file: %w", err)
			}
			return deps, nil
		} else if strings.HasSuffix(projectPath, "package.json") {
			deps, err := project.ParsePackageJSON(projectPath)
			if err != nil {
				return nil, fmt.Errorf("failed to parse project file: %w", err)
			}
			return deps, nil
		}
		return nil, fmt.Errorf("invalid project path: must be package.json or package-lock.json")
	}
	if auditNodeModules {
		deps, err := project.AuditNodeModules(".")
		if err != nil {
			return nil, fmt.Errorf("failed to scan node_modules: %w", err)
		}
		return deps, nil
	}
	if len(args) > 0 {
		return []project.Dependency{{Name: args[0]}}, nil
	}
	return nil, fmt.Errorf("package name, --project path, or --node-modules is required")
}

func resolveMinSeverity() (analyzer.Severity, error) {
	if minSeverity == "" {
		return 0, nil
	}
	return parseSeverity(minSeverity)
}

func resolveOutput() (io.Writer, func(), error) {
	if outputFile == "" {
		return os.Stdout, nil, nil
	}
	f, err := os.Create(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output file: %w", err)
	}
	return f, func() { f.Close() }, nil
}

func buildAnalyzers() []analyzer.Analyzer {
	analyzers := []analyzer.Analyzer{
		analyzer.NewVulnAnalyzer(),
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
	}
	if !noSandbox {
		analyzers = append(analyzers, analyzer.NewSandboxAnalyzer())
	}
	return analyzers
}

func buildProjectReport(deps []project.Dependency, sev analyzer.Severity, client *registry.Client, analyzers []analyzer.Analyzer) reporter.ProjectReport {
	var projectReport reporter.ProjectReport
	projectReport.ProjectName = projectPath
	if auditNodeModules {
		projectReport.ProjectName = "node_modules"
	}

	if concurrency < 1 {
		concurrency = 1
	}

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, concurrency)
	)

	for _, dep := range deps {
		wg.Add(1)
		go func(d project.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			report := auditPackage(d, sev, client, analyzers)
			if report != nil {
				mu.Lock()
				projectReport.Reports = append(projectReport.Reports, *report)
				mu.Unlock()
			}
		}(dep)
	}
	wg.Wait()

	sort.Slice(projectReport.Reports, func(i, j int) bool {
		return projectReport.Reports[i].Package < projectReport.Reports[j].Package
	})

	return projectReport
}

func auditPackage(d project.Dependency, sev analyzer.Severity, client *registry.Client, analyzers []analyzer.Analyzer) *reporter.Report {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	if format == "terminal" && outputFile == "" {
		fmt.Fprintf(os.Stderr, "Auditing %s...\n", d.Name)
	}

	pkg, err := client.GetPackage(ctx, d.Name)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Skipping %s: %v\n", d.Name, err)
		}
		return nil
	}

	verName := resolveVersion(d, pkg)
	if verName == "" {
		return nil
	}

	version, ok := pkg.Versions[verName]
	if !ok {
		if verbose {
			fmt.Fprintf(os.Stderr, "Skipping %s: version %s not found\n", d.Name, verName)
		}
		return nil
	}

	results := analyzer.RunAll(ctx, analyzers, pkg, &version)
	if minSeverity != "" {
		for i := range results {
			results[i].Findings = analyzer.FilterByMinSeverity(results[i].Findings, sev)
		}
	}

	info := buildPackageInfo(ctx, d.Name, pkg, &version, client)

	return &reporter.Report{
		Package: d.Name,
		Version: verName,
		Results: results,
		Info:    info,
	}
}

func resolveVersion(d project.Dependency, pkg *registry.PackageMetadata) string {
	verName := d.Version
	if verName == "" || strings.HasPrefix(verName, "^") || strings.HasPrefix(verName, "~") {
		latestTag, ok := pkg.DistTags["latest"]
		if !ok {
			if verbose {
				fmt.Fprintf(os.Stderr, "Skipping %s: no latest tag\n", d.Name)
			}
			return ""
		}
		return latestTag
	}
	return verName
}

func buildPackageInfo(ctx context.Context, name string, pkg *registry.PackageMetadata, version *registry.PackageVersion, client *registry.Client) reporter.PackageInfo {
	info := reporter.PackageInfo{
		License:       version.License,
		TotalVersions: len(pkg.Versions),
		Dependencies:  len(version.Dependencies),
		HasScripts:    hasInstallScripts(version),
	}
	for _, m := range pkg.Maintainers {
		info.Maintainers = append(info.Maintainers, m.Name)
	}
	if pkg.Repository != nil && pkg.Repository.URL != "" {
		info.RepoURL = pkg.Repository.URL
	}
	if created, ok := pkg.Time["created"]; ok {
		info.CreatedAt = created.Format("2006-01-02")
	}

	downloads, dlErr := client.GetDownloads(ctx, name)
	if dlErr == nil && downloads != nil {
		repInfo := reputation.Build(name, downloads.Downloads)
		info.WeeklyDownloads = repInfo.WeeklyDownloads
		info.DownloadTier = string(repInfo.DownloadTier)
		info.IsTrustedScope = repInfo.IsTrustedScope
		info.TrustedScopeOrg = repInfo.TrustedScopeOrg
		info.ReputationScore = repInfo.ReputationScore
	}

	return info
}

func isMultiPackageAudit(deps []project.Dependency) bool {
	return len(deps) > 1 || projectPath != "" || auditNodeModules
}

func renderReport(rep *reporter.Reporter, projectReport reporter.ProjectReport, deps []project.Dependency) error {
	if isMultiPackageAudit(deps) {
		return rep.RenderProject(projectReport)
	}
	if len(projectReport.Reports) > 0 {
		return rep.Render(projectReport.Reports[0])
	}
	return nil
}

func renderAISummary(out io.Writer, projectReport reporter.ProjectReport, deps []project.Dependency) {
	var jsonBuf strings.Builder
	jsonEnc := json.NewEncoder(&jsonBuf)
	jsonEnc.SetIndent("", "  ")
	if isMultiPackageAudit(deps) {
		jsonEnc.Encode(projectReport)
	} else {
		jsonEnc.Encode(projectReport.Reports[0])
	}

	summary, err := ai.GenerateSummary([]byte(jsonBuf.String()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%sAI Summary unavailable: %s%s\n", "\033[33m", err, "\033[0m")
	} else {
		fmt.Fprintf(out, "\n%s╔══════════════════════════════════════════════════════════════════════╗%s\n", "\033[1;36m", "\033[0m")
		fmt.Fprintf(out, "%s║  AI Analysis (Gemini)                                                ║%s\n", "\033[1;36m", "\033[0m")
		fmt.Fprintf(out, "%s╚══════════════════════════════════════════════════════════════════════╝%s\n", "\033[1;36m", "\033[0m")
		fmt.Fprintln(out)
		fmt.Fprintln(out, summary)
		fmt.Fprintln(out)
	}
}
func hasInstallScripts(v *registry.PackageVersion) bool {
	if v.HasInstallScript {
		return true
	}
	if v.Scripts == nil {
		return false
	}
	for _, name := range []string{"preinstall", "install", "postinstall"} {
		if _, ok := v.Scripts[name]; ok {
			return true
		}
	}
	return false
}

func parseSeverity(s string) (analyzer.Severity, error) {
	switch s {
	case "low":
		return analyzer.SeverityLow, nil
	case "medium":
		return analyzer.SeverityMedium, nil
	case "high":
		return analyzer.SeverityHigh, nil
	case "critical":
		return analyzer.SeverityCritical, nil
	default:
		return 0, fmt.Errorf("invalid severity %q: must be low, medium, high, or critical", s)
	}
}
