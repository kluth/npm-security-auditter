package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	"gopkg.in/yaml.v3"
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
	quiet            bool
	failOn           string
	listAnalyzers    bool
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
		Version: "2.2.0",
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
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress messages to stderr")
	rootCmd.Flags().StringVar(&failOn, "fail-on", "", "exit with code 2 if any finding meets/exceeds severity (low, medium, high, critical)")
	rootCmd.Flags().BoolVar(&listAnalyzers, "list-analyzers", false, "list all available analyzers and exit")
	rootCmd.Flags().BoolVar(&aiSummary, "ai-summary", false, "generate AI analysis via Gemini CLI")

	if err := rootCmd.Execute(); err != nil {
		if exitErr, ok := err.(*ExitError); ok {
			fmt.Fprintln(os.Stderr, exitErr.Message)
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}

// ExitError signals a non-standard exit code (e.g., 2 for --fail-on).
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string { return e.Message }

func stderrPrintf(format string, a ...interface{}) {
	if !quiet {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

func loadConfiguration(cmd *cobra.Command) error {
	if cfgPath := findConfigFile(); cfgPath != "" {
		cfg, err := loadConfigFile(cfgPath)
		if err != nil {
			return err
		}
		applyConfig(cfg)
	}
	resolveConfig(cmd)
	if quiet && verbose {
		return fmt.Errorf("--quiet and --verbose are mutually exclusive")
	}
	if failOn != "" {
		if _, err := parseSeverity(failOn); err != nil {
			return err
		}
	}
	return nil
}

func runAudit(args []string) error {
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

	if err := renderReport(rep, projectReport, deps); err != nil {
		return err
	}
	if aiSummary && len(projectReport.Reports) > 0 {
		renderAISummary(out, projectReport, deps)
	}
	if failOn != "" {
		return checkFailOn(projectReport, failOn)
	}
	return nil
}

func run(cmd *cobra.Command, args []string) error {
	if err := loadConfiguration(cmd); err != nil {
		return err
	}
	if listAnalyzers {
		printAnalyzerList(os.Stdout)
		return nil
	}
	if interactive {
		p := tea.NewProgram(initialModel())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("error running TUI: %w", err)
		}
		return nil
	}
	return runAudit(args)
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
		stderrPrintf("Auditing %s...\n", d.Name)
	}

	pkg, err := client.GetPackage(ctx, d.Name)
	if err != nil {
		if verbose {
			stderrPrintf("Skipping %s: %v\n", d.Name, err)
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
			stderrPrintf("Skipping %s: version %s not found\n", d.Name, verName)
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
				stderrPrintf("Skipping %s: no latest tag\n", d.Name)
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

func flagChanged(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	f := cmd.Flags().Lookup(name)
	return f != nil && f.Changed
}

func resolveStringEnv(cmd *cobra.Command, flagName, envKey string, target *string) {
	if flagChanged(cmd, flagName) {
		return
	}
	if v := os.Getenv(envKey); v != "" {
		*target = v
	}
}

func resolveIntEnv(cmd *cobra.Command, flagName, envKey string, target *int) {
	if flagChanged(cmd, flagName) {
		return
	}
	if v := os.Getenv(envKey); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*target = n
		}
	}
}

func resolveBoolEnv(cmd *cobra.Command, flagName, envKey string, target *bool) {
	if flagChanged(cmd, flagName) {
		return
	}
	if v := os.Getenv(envKey); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			*target = b
		}
	}
}

type configFile struct {
	Registry    string `yaml:"registry"`
	Format      string `yaml:"format"`
	Lang        string `yaml:"lang"`
	Severity    string `yaml:"severity"`
	FailOn      string `yaml:"fail-on"`
	Timeout     int    `yaml:"timeout"`
	Concurrency int    `yaml:"concurrency"`
	NoSandbox   bool   `yaml:"no-sandbox"`
	Quiet       bool   `yaml:"quiet"`
}

func loadConfigFile(path string) (*configFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", path, err)
	}
	return &cfg, nil
}

func findConfigFile() string {
	if _, err := os.Stat(".auditter.yaml"); err == nil {
		return ".auditter.yaml"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(home, ".config", "auditter", "config.yaml")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func applyConfig(cfg *configFile) {
	if cfg == nil {
		return
	}
	if cfg.Registry != "" {
		registryURL = cfg.Registry
	}
	if cfg.Format != "" {
		format = cfg.Format
	}
	if cfg.Lang != "" {
		lang = cfg.Lang
	}
	if cfg.Severity != "" {
		minSeverity = cfg.Severity
	}
	if cfg.FailOn != "" {
		failOn = cfg.FailOn
	}
	if cfg.Timeout != 0 {
		timeout = cfg.Timeout
	}
	if cfg.Concurrency != 0 {
		concurrency = cfg.Concurrency
	}
	if cfg.NoSandbox {
		noSandbox = true
	}
	if cfg.Quiet {
		quiet = true
	}
}

func resolveConfig(cmd *cobra.Command) {
	resolveStringEnv(cmd, "registry", "AUDITTER_REGISTRY", &registryURL)
	resolveStringEnv(cmd, "format", "AUDITTER_FORMAT", &format)
	resolveStringEnv(cmd, "lang", "AUDITTER_LANG", &lang)
	resolveStringEnv(cmd, "severity", "AUDITTER_SEVERITY", &minSeverity)
	resolveStringEnv(cmd, "fail-on", "AUDITTER_FAIL_ON", &failOn)
	resolveIntEnv(cmd, "timeout", "AUDITTER_TIMEOUT", &timeout)
	resolveIntEnv(cmd, "concurrency", "AUDITTER_CONCURRENCY", &concurrency)
	resolveBoolEnv(cmd, "no-sandbox", "AUDITTER_NO_SANDBOX", &noSandbox)
	resolveBoolEnv(cmd, "quiet", "AUDITTER_QUIET", &quiet)
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

func checkFailOn(pr reporter.ProjectReport, threshold string) error {
	sev, _ := parseSeverity(threshold) // already validated
	for _, report := range pr.Reports {
		for _, result := range report.Results {
			for _, f := range result.Findings {
				if f.Severity >= sev {
					return &ExitError{
						Code:    2,
						Message: fmt.Sprintf("findings at or above %q severity detected", threshold),
					}
				}
			}
		}
	}
	return nil
}

// AnalyzerInfo describes a registered analyzer for --list-analyzers output.
type AnalyzerInfo struct {
	Name        string
	Category    string
	Description string
}

func analyzerRegistry() []AnalyzerInfo {
	return []AnalyzerInfo{
		{"vulnerabilities", "Supply Chain", "Check for known CVEs and security advisories"},
		{"install-scripts", "Supply Chain", "Detect suspicious install lifecycle scripts"},
		{"typosquatting", "Supply Chain", "Detect package name typosquatting attacks"},
		{"slopsquatting", "Supply Chain", "Detect LLM-hallucinated package names"},
		{"maintainers", "Supply Chain", "Analyze maintainer trust signals"},
		{"metadata", "Supply Chain", "Check package metadata for anomalies"},
		{"dependencies", "Supply Chain", "Analyze dependency tree for risks"},
		{"remote-dependencies", "Supply Chain", "Detect HTTP URL and git dependencies"},
		{"binary-analysis", "Code Analysis", "Detect binary/compiled code in packages"},
		{"provenance", "Build Integrity", "Verify SLSA provenance attestations"},
		{"tarball-analysis", "Code Analysis", "Deep scan tarball contents for threats"},
		{"repo-verification", "Supply Chain", "Verify repository URL authenticity"},
		{"repository-issues", "Supply Chain", "Analyze GitHub issues for security reports"},
		{"dangerous-shell-scripts", "Code Analysis", "Analyze shell scripts for dangerous commands"},
		{"ossf-scorecard", "Supply Chain", "OpenSSF Scorecard-style security checks"},
		{"commit-history", "Supply Chain", "Analyze git commit patterns for risks"},
		{"download-patterns", "Supply Chain", "Analyze download patterns for anomalies"},
		{"manifest-confusion", "Supply Chain", "Detect manifest vs tarball mismatches"},
		{"version-anomalies", "Supply Chain", "Detect suspicious version publish patterns"},
		{"starjacking", "Supply Chain", "Detect repository star-jacking attacks"},
		{"community-trust", "Supply Chain", "Evaluate open source community signals"},
		{"reproducible-build", "Build Integrity", "Verify build reproducibility"},
		{"code-signing", "Build Integrity", "Verify code signing and integrity"},
		{"dynamic-analysis", "Runtime Analysis", "Dynamic analysis in isolated sandbox"},
		{"ast-analysis", "Code Analysis", "Deep JavaScript AST-based analysis"},
		{"taint-analysis", "Code Analysis", "Data flow taint tracking analysis"},
		{"env-fingerprinting", "Malware Detection", "Detect CI/CD and environment fingerprinting"},
		{"multilayer-obfuscation", "Malware Detection", "Detect nested obfuscation techniques"},
		{"anti-debug", "Malware Detection", "Detect anti-debugging techniques"},
		{"phantom-deps", "Supply Chain", "Detect undeclared phantom dependencies"},
		{"timebomb", "Malware Detection", "Detect time-based payload activation"},
		{"crypto-theft", "Malware Detection", "Detect cryptocurrency theft patterns"},
		{"multistage-loader", "Malware Detection", "Detect multi-stage payload loaders"},
		{"proto-pollution", "Code Analysis", "Detect prototype pollution patterns"},
		{"worm", "Malware Detection", "Detect self-propagating worm behavior"},
		{"phishing", "Malware Detection", "Detect credential phishing techniques"},
		{"side-effects", "Code Analysis", "Detect unexpected module side effects"},
		{"telemetry", "Code Analysis", "Detect hidden telemetry and tracking"},
		{"environment-variables", "Malware Detection", "Detect environment variable exfiltration"},
		{"network-security", "Runtime Analysis", "Analyze network communication patterns"},
		{"dangerous-extensions", "Code Analysis", "Detect dangerous file extensions in packages"},
		{"suspicious-urls", "Code Analysis", "Detect suspicious URL patterns in code"},
		{"exfiltration-endpoints", "Malware Detection", "Detect data exfiltration attempts"},
		{"behavior-sequence", "Runtime Analysis", "Behavioral sequence analysis of execution"},
		{"lockfile-analysis", "Supply Chain", "Analyze lockfile integrity and consistency"},
		{"ai-evasion", "Malware Detection", "Detect AI/ML evasion techniques"},
		{"minified-only", "Code Analysis", "Detect packages with only minified code"},
	}
}

func printAnalyzerList(w io.Writer) {
	infos := analyzerRegistry()
	nameW, catW := 0, 0
	for _, info := range infos {
		if len(info.Name) > nameW {
			nameW = len(info.Name)
		}
		if len(info.Category) > catW {
			catW = len(info.Category)
		}
	}
	fmt.Fprintf(w, "%-*s  %-*s  %s\n", nameW, "ANALYZER", catW, "CATEGORY", "DESCRIPTION")
	fmt.Fprintf(w, "%-*s  %-*s  %s\n", nameW, strings.Repeat("-", nameW), catW, strings.Repeat("-", catW), strings.Repeat("-", 40))
	for _, info := range infos {
		fmt.Fprintf(w, "%-*s  %-*s  %s\n", nameW, info.Name, catW, info.Category, info.Description)
	}
	fmt.Fprintf(w, "\nTotal: %d analyzers\n", len(infos))
}
