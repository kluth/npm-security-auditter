package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/kluth/npm-security-auditter/internal/ai"
	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/audit"
	"github.com/kluth/npm-security-auditter/internal/intelligence"
	"github.com/kluth/npm-security-auditter/internal/policy"
	"github.com/kluth/npm-security-auditter/internal/reporter"
	"github.com/kluth/npm-security-auditter/internal/tui"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
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
	aiClaude         bool
	limitTop         int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "auditter [package-name]",
		Short: "Audit npm packages for security risks",
		Long: fmt.Sprintf(`auditter performs a comprehensive security audit of npm packages.
		
		It checks for known vulnerabilities, suspicious install scripts,
		typosquatting, maintainer risks, metadata anomalies, dependency
		issues, binary/obfuscated code, supply chain provenance,
		tarball contents, repository verification, and behavior in a sandbox environment.
		
		Build Info: Commit %s, Date %s
		
		Examples:  auditter lodash
  auditter express --json --output report.json
  auditter --project package.json --severity high
  auditter --node-modules --format html --output audit.html`, commit, date),
		Version: version,
		Args:    cobra.ArbitraryArgs,
		RunE:    run,
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "tree",
		Short: "Visualize dependency tree (demo)",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := tea.NewProgram(tui.NewTreeModel())
			_, err := p.Run()
			return err
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "audit-top [category]",
		Short: "Audit top npm packages by category from GitHub",
		Long:  `Search GitHub for top repositories in a specific category/topic (e.g. web-framework, utility, testing) and audit their corresponding npm packages.`,
		RunE:  runAuditTop,
	})

	rootCmd.AddCommand(newMcpCmd())

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
	rootCmd.Flags().BoolVar(&aiClaude, "ai-claude", false, "generate AI analysis via Claude CLI")
	rootCmd.Flags().IntVar(&limitTop, "limit", 10, "number of top repositories to audit")

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
	// Determine target
	var target string
	if len(args) > 0 {
		target = args[0]
	} else if projectPath != "" {
		target = projectPath
	} else if auditNodeModules {
		target = "." // current dir for node_modules
	} else {
		return fmt.Errorf("package name, --project path, or --node-modules is required")
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

	// Configure Runner
	cfg := audit.Config{
		RegistryURL:      registryURL,
		Timeout:          timeout,
		Concurrency:      concurrency,
		MinSeverity:      sev,
		NoSandbox:        noSandbox,
		AuditNodeModules: auditNodeModules,
		ProjectPath:      projectPath,
		Verbose:          verbose,
	}

	runner := audit.NewRunner(cfg)
	
	// Pre-load dependencies if just checking single package or specific cases?
	// The runner handles resolution now, so we just pass the target.
	// But wait, resolveDependencies handled some logic.
	// If projectPath is set, Runner uses it from cfg.ProjectPath.
	// If auditNodeModules is set, Runner uses it.
	// If args[0] is passed, we should pass it to Run.
	
	// However, `resolveDependencies` in main.go returned []Dependency.
	// Runner.Run takes a nameOrPath.
	// Let's rely on Runner's logic which matches what we moved there.
	
	// IMPORTANT: Runner uses cfg.ProjectPath or cfg.AuditNodeModules preferentially.
	// If neither, it treats nameOrPath as package name.
	
	// If both projectPath and args are missing, Runner.Run(ctx, "") might fail if config doesn't specify project.
	// But main logic ensures we have a target.

	ctx := context.Background()
	projectReport, err := runner.Run(ctx, target)
	if err != nil {
		return err
	}

	rep := reporter.NewWithOptions(out, format, reporter.Language(lang), verbose)
	
	// We need deps list for AI summary or just use the report?
	// The new renderAISummary uses projectReport directly mostly.
	// But it checks `isMultiPackageAudit(deps)`.
	// We can infer multi-package from len(projectReport.Reports) or config.
	
	// Reconstruct simplified deps for legacy compatibility if needed, or update render functions.
	// Actually, let's just use what we have.
	// `renderReport` and `renderAISummary` need `[]project.Dependency`.
	// We can synthesize it from the report if needed, or just change the signature.
	// Let's change the signature of render functions to not need `deps`.
	
	if err := renderReport(rep, projectReport); err != nil {
		return err
	}
	
	if (aiSummary || aiClaude) && len(projectReport.Reports) > 0 {
		if err := renderAISummary(out, projectReport); err != nil {
			stderrPrintf("Warning: failed to render AI summary: %v\n", err)
		}
	}
	
	if failOn != "" {
		return checkFailOn(projectReport, failOn)
	}

	// Policy check
	if cfgPath := findConfigFile(); cfgPath != "" {
		cfg, _ := loadConfigFile(cfgPath)
		if cfg != nil && (cfg.Policy.MaxSeverity > 0 || len(cfg.Policy.BannedLicenses) > 0 || !cfg.Policy.AllowScripts || len(cfg.Policy.BannedPackages) > 0) {
			violations := policy.Evaluate(&projectReport, &cfg.Policy)
			if len(violations) > 0 {
				fmt.Fprintln(os.Stderr, "\nPolicy Violations Detected:")
				for _, v := range violations {
					fmt.Fprintf(os.Stderr, " - %s\n", v)
				}
				return &ExitError{Code: 3, Message: "Policy check failed"}
			}
		}
	}

	return nil
}

func run(cmd *cobra.Command, args []string) error {
	if err := loadConfiguration(cmd); err != nil {
		return err
	}
	if listAnalyzers {
		audit.PrintAnalyzerList(os.Stdout)
		return nil
	}
	if interactive {
		if err := runTUI(); err != nil {
			return err
		}
		return nil
	}
	return runAudit(args)
}

func runAuditTop(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		fmt.Println("Available GitHub categories/topics for top repositories:")
		for _, cat := range intelligence.GetDefaultCategories() {
			fmt.Printf("- %s\n", cat)
		}
		fmt.Println("\nUse: auditter audit-top [category]")
		return nil
	}

	category := args[0]
	fmt.Printf("Searching GitHub for top %d repositories in category %q...\n", limitTop, category)

	deps, err := intelligence.FetchTopReposByCategory(context.Background(), category, limitTop)
	if err != nil {
		return err
	}

	if len(deps) == 0 {
		return fmt.Errorf("no repositories found for category %q", category)
	}

	if err := loadConfiguration(cmd); err != nil {
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

	// We can't use audit.Runner directly for "Top Repos" easily because Runner expects project/node_modules/single package.
	// But we can manually construct the runner's behavior or just add "Batch Audit" to Runner?
	// Actually, Runner.RunTopRepos? Or just use Runner.executeAudit if we expose it?
	// It's not exported.
	// Let's manually run it using the new internal/audit components if possible, or just duplicate the loop here for now to avoid over-engineering the Runner for this specific case.
	// Or better: Let's expose `Runner.AuditPackage`?
	// No, let's keep it simple.
	
	// Refactor: We can use the Runner if we change how it accepts input.
	// For now, I will use the Runner's internal components via a helper or just duplicate the "loop over deps" logic here using `audit.NewRunner` config but manual execution?
	// No, `Runner` encapsulates the client and intel.
	
	// Let's add `AuditBatch` to Runner.
	// I'll skip that for now and just instantiate `audit.NewRunner` and use a new method I'll add to `audit` package: `RunBatch`.
	// For now, since I can't edit `audit.go` in this request (I already wrote it), I will have to add `RunBatch` to `audit.go` in a separate tool call if I want to use it.
	// Or I can just manually do what `executeAudit` does, but I can't access `auditPackage` (unexported).
	
	// OK, I need to export `AuditPackage` or add `RunBatch` to `audit.go`.
	// I will add `RunBatch` to `audit.go` in next step.
	// For this `replace` call, I will assume `runner.RunBatch(ctx, deps)` exists.
	
	cfg := audit.Config{
		RegistryURL: registryURL,
		Timeout:     timeout,
		Concurrency: concurrency,
		MinSeverity: sev,
		NoSandbox:   noSandbox,
		Verbose:     verbose,
	}
	runner := audit.NewRunner(cfg)
	
	projectReport, err := runner.RunBatch(context.Background(), deps)
	if err != nil {
		return err
	}
	projectReport.ProjectName = category

	rep := reporter.NewWithOptions(out, format, reporter.Language(lang), verbose)

	if format == "terminal" && !verbose {
		if err := rep.RenderTopList(projectReport); err != nil {
			return err
		}
	} else {
		if err := renderReport(rep, projectReport); err != nil {
			return err
		}
	}

	if (aiSummary || aiClaude) && len(projectReport.Reports) > 0 {
		if err := renderAISummary(out, projectReport); err != nil {
			stderrPrintf("Warning: failed to render AI summary: %v\n", err)
		}
	}

	if failOn != "" {
		return checkFailOn(projectReport, failOn)
	}

	return nil
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

func isMultiPackageAudit(pr reporter.ProjectReport) bool {
	return len(pr.Reports) > 1 || projectPath != "" || auditNodeModules
}

func renderReport(rep *reporter.Reporter, projectReport reporter.ProjectReport) error {
	if isMultiPackageAudit(projectReport) {
		return rep.RenderProject(projectReport)
	}
	if len(projectReport.Reports) > 0 {
		return rep.Render(projectReport.Reports[0])
	}
	return nil
}

func renderAISummary(out io.Writer, projectReport reporter.ProjectReport) error {
	var jsonBuf strings.Builder
	jsonEnc := json.NewEncoder(&jsonBuf)
	jsonEnc.SetIndent("", "  ")
	var err error
	if isMultiPackageAudit(projectReport) {
		err = jsonEnc.Encode(projectReport)
	} else {
		err = jsonEnc.Encode(projectReport.Reports[0])
	}
	if err != nil {
		return fmt.Errorf("failed to encode report for AI summary: %w", err)
	}

	var summary string
	var providerName string

	if aiClaude {
		if isMultiPackageAudit(projectReport) {
			summary, err = ai.GenerateClaudeTopListSummary([]byte(jsonBuf.String()))
		} else {
			summary, err = ai.GenerateClaudeSummary([]byte(jsonBuf.String()))
		}
		providerName = "Claude"
	} else {
		if isMultiPackageAudit(projectReport) {
			summary, err = ai.GenerateTopListSummary([]byte(jsonBuf.String()))
		} else {
			summary, err = ai.GenerateSummary([]byte(jsonBuf.String()))
		}
		providerName = "Gemini"
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%sAI Summary (%s) unavailable: %s%s\n", "\033[33m", providerName, err, "\033[0m")
		return nil // Not a fatal error
	}

	fmt.Fprintf(out, "\n%s╔══════════════════════════════════════════════════════════════════════╗%s\n", "\033[1;36m", "\033[0m")
	fmt.Fprintf(out, "%s║  AI Analysis (%-10s)                                          ║%s\n", "\033[1;36m", providerName, "\033[0m")
	fmt.Fprintf(out, "%s╚══════════════════════════════════════════════════════════════════════╝%s\n", "\033[1;36m", "\033[0m")
	fmt.Fprintln(out)
	fmt.Fprintln(out, summary)
	fmt.Fprintln(out)
	return nil
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
	Registry    string        `yaml:"registry"`
	Format      string        `yaml:"format"`
	Lang        string        `yaml:"lang"`
	Severity    string        `yaml:"severity"`
	FailOn      string        `yaml:"fail-on"`
	Timeout     int           `yaml:"timeout"`
	Concurrency int           `yaml:"concurrency"`
	NoSandbox   bool          `yaml:"no-sandbox"`
	Quiet       bool          `yaml:"quiet"`
	Policy      policy.Policy `yaml:"policy"`
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
