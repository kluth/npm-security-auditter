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

	"github.com/kluth/npm-security-auditter/internal/ai"
	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/reporter"
	"github.com/kluth/npm-security-auditter/internal/reputation"
	"github.com/kluth/npm-security-auditter/internal/project"
	"github.com/spf13/cobra"
	tea "github.com/charmbracelet/bubbletea"
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

	var deps []project.Dependency
	var err error

	if projectPath != "" {
		if strings.HasSuffix(projectPath, "package-lock.json") {
			deps, err = project.ParsePackageLock(projectPath)
		} else if strings.HasSuffix(projectPath, "package.json") {
			deps, err = project.ParsePackageJSON(projectPath)
		} else {
			return fmt.Errorf("invalid project path: must be package.json or package-lock.json")
		}
		if err != nil {
			return fmt.Errorf("failed to parse project file: %w", err)
		}
	} else if auditNodeModules {
		deps, err = project.AuditNodeModules(".")
		if err != nil {
			return fmt.Errorf("failed to scan node_modules: %w", err)
		}
	} else if len(args) > 0 {
		deps = []project.Dependency{{Name: args[0]}}
	} else {
		return fmt.Errorf("package name, --project path, or --node-modules is required")
	}

	        if jsonOutput {
	                format = "json"
	        }
	
	        var sev analyzer.Severity
	        if minSeverity != "" {
	                var err error
	                sev, err = parseSeverity(minSeverity)
	                if err != nil {
	                        return err
	                }
	        }
	
	                var out io.Writer = os.Stdout
	
	                if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	rep := reporter.NewWithOptions(out, format, reporter.Language(lang), verbose)
	var projectReport reporter.ProjectReport
	projectReport.ProjectName = projectPath
	if auditNodeModules {
		projectReport.ProjectName = "node_modules"
	}

	client := registry.NewClient(registryURL)
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

	if concurrency < 1 {
		concurrency = 1
	}

	var (
		wg sync.WaitGroup
		mu sync.Mutex
		sem = make(chan struct{}, concurrency)
	)

	for _, dep := range deps {
		wg.Add(1)
		go func(d project.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

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
				return
			}

			verName := d.Version
			if verName == "" || strings.HasPrefix(verName, "^") || strings.HasPrefix(verName, "~") {
				latestTag, ok := pkg.DistTags["latest"]
				if !ok {
					if verbose {
						fmt.Fprintf(os.Stderr, "Skipping %s: no latest tag\n", d.Name)
					}
					return
				}
				verName = latestTag
			}

			version, ok := pkg.Versions[verName]
			if !ok {
				if verbose {
					fmt.Fprintf(os.Stderr, "Skipping %s: version %s not found\n", d.Name, verName)
				}
				return
			}

			                                                results := analyzer.RunAll(ctx, analyzers, pkg, &version)

			                                                if minSeverity != "" {

			                                                        for i := range results {

			                                                                results[i].Findings = analyzer.FilterByMinSeverity(results[i].Findings, sev)

			                                                        }

			                                                }

			                        

			                                                                        info := reporter.PackageInfo{

			                        

			                                                                                License:       version.License,

			                        

			                                                                                TotalVersions: len(pkg.Versions),

			                        

			                                                                                Dependencies:  len(version.Dependencies),

			                        

			                                                                                HasScripts:    hasInstallScripts(&version),

			                        

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

			// Fetch download stats and build reputation info
			downloads, dlErr := client.GetDownloads(ctx, d.Name)
			if dlErr == nil && downloads != nil {
				repInfo := reputation.Build(d.Name, downloads.Downloads)
				info.WeeklyDownloads = repInfo.WeeklyDownloads
				info.DownloadTier = string(repInfo.DownloadTier)
				info.IsTrustedScope = repInfo.IsTrustedScope
				info.TrustedScopeOrg = repInfo.TrustedScopeOrg
				info.ReputationScore = repInfo.ReputationScore
			}

			mu.Lock()
			projectReport.Reports = append(projectReport.Reports, reporter.Report{
				Package: d.Name,
				Version: verName,
				Results: results,
				Info:    info,
			})
			mu.Unlock()
		}(dep)
	}
	wg.Wait()

	sort.Slice(projectReport.Reports, func(i, j int) bool {
		return projectReport.Reports[i].Package < projectReport.Reports[j].Package
	})

	var renderErr error
	if len(deps) > 1 || projectPath != "" || auditNodeModules {
		renderErr = rep.RenderProject(projectReport)
	} else if len(projectReport.Reports) > 0 {
		renderErr = rep.Render(projectReport.Reports[0])
	}

	if renderErr != nil {
		return renderErr
	}

	// Generate AI summary if requested
	if aiSummary && len(projectReport.Reports) > 0 {
		// Generate JSON for AI analysis
		var jsonBuf strings.Builder
		jsonEnc := json.NewEncoder(&jsonBuf)
		jsonEnc.SetIndent("", "  ")
		if len(deps) > 1 || projectPath != "" || auditNodeModules {
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

	return nil
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
