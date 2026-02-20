package audit

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/intelligence"
	"github.com/kluth/npm-security-auditter/internal/project"
	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/reporter"
	"github.com/kluth/npm-security-auditter/internal/reputation"
)

// Config holds the audit configuration.
type Config struct {
	RegistryURL      string
	Timeout          int
	Concurrency      int
	MinSeverity      analyzer.Severity
	NoSandbox        bool
	AuditNodeModules bool
	ProjectPath      string
	Verbose          bool
}

// Runner handles audit execution.
type Runner struct {
	cfg      Config
	client   *registry.Client
	intelMgr *intelligence.Manager
}

// NewRunner creates a new Runner with the given configuration.
func NewRunner(cfg Config) *Runner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 180
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 5
	}
	
	intelMgr := intelligence.NewManager("")
	_ = intelMgr.Load() // Ignore error, continue with empty intel if needed

	return &Runner{
		cfg:      cfg,
		client:   registry.NewClient(cfg.RegistryURL),
		intelMgr: intelMgr,
	}
}

// RunBatch executes the audit for a pre-resolved list of dependencies.
func (r *Runner) RunBatch(ctx context.Context, deps []project.Dependency) (reporter.ProjectReport, error) {
	var projectReport reporter.ProjectReport
	projectReport.ProjectName = r.cfg.ProjectPath
	if r.cfg.AuditNodeModules {
		projectReport.ProjectName = "node_modules"
	}
	if projectReport.ProjectName == "" && len(deps) == 1 {
		projectReport.ProjectName = deps[0].Name
	}

	analyzers := r.buildAnalyzers()
	concurrency := r.cfg.Concurrency
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

			report := r.auditPackage(ctx, d, analyzers)
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

	return projectReport, nil
}

func (r *Runner) Run(ctx context.Context, nameOrPath string) (reporter.ProjectReport, error) {
	var deps []project.Dependency
	var err error

	if r.cfg.AuditNodeModules {
		deps, err = project.AuditNodeModules(nameOrPath)
		if err != nil {
			return reporter.ProjectReport{}, err
		}
	} else if r.cfg.ProjectPath != "" {
		if strings.HasSuffix(r.cfg.ProjectPath, "package-lock.json") {
			deps, err = project.ParsePackageLock(r.cfg.ProjectPath)
		} else if strings.HasSuffix(r.cfg.ProjectPath, "package.json") {
			deps, err = project.ParsePackageJSON(r.cfg.ProjectPath)
		} else {
			return reporter.ProjectReport{}, fmt.Errorf("invalid project path: must be package.json or package-lock.json")
		}
	} else {
		// Single package
		deps = []project.Dependency{{Name: nameOrPath}}
	}

	if err != nil {
		return reporter.ProjectReport{}, err
	}

	return r.RunBatch(ctx, deps)
}

func (r *Runner) auditPackage(ctx context.Context, d project.Dependency, analyzers []analyzer.Analyzer) *reporter.Report {
	// Create a sub-context for each package with timeout
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.cfg.Timeout)*time.Second)
	defer cancel()

	pkg, err := r.client.GetPackage(ctx, d.Name)
	if err != nil {
		return nil
	}

	verName := resolveVersion(d, pkg)
	if verName == "" {
		return nil
	}

	version, ok := pkg.Versions[verName]
	if !ok {
		return nil
	}

	results := analyzer.RunAll(ctx, analyzers, pkg, &version)
	if r.cfg.MinSeverity != 0 {
		for i := range results {
			results[i].Findings = analyzer.FilterByMinSeverity(results[i].Findings, r.cfg.MinSeverity)
		}
	}

	info := buildPackageInfo(ctx, d.Name, pkg, &version, r.client)
	
	// Calculate score
	score := 0
	if info.WeeklyDownloads > 0 || info.IsTrustedScope {
		score = reporter.CalculateRiskScoreWithReputation(results, info)
	} else {
		score = reporter.CalculateRiskScore(results)
	}

	return &reporter.Report{
		Package: d.Name,
		Version: verName,
		Results: results,
		Info:    info,
		Score:   score,
	}
}

func (r *Runner) buildAnalyzers() []analyzer.Analyzer {
	analyzers := []analyzer.Analyzer{
		analyzer.NewVulnAnalyzer(),
		analyzer.NewIntelAnalyzer(r.intelMgr),
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
	if !r.cfg.NoSandbox {
		analyzers = append(analyzers, analyzer.NewSandboxAnalyzer())
	}
	return analyzers
}

func resolveVersion(d project.Dependency, pkg *registry.PackageMetadata) string {
	verName := d.Version
	if verName == "" || strings.HasPrefix(verName, "^") || strings.HasPrefix(verName, "~") {
		latestTag, ok := pkg.DistTags["latest"]
		if !ok {
			return ""
		}
		return latestTag
	}
	return verName
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

// PrintAnalyzerList prints the list of available analyzers.
func PrintAnalyzerList(w io.Writer) {
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

// AnalyzerInfo describes a registered analyzer.
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
		{"unicode-steganography", "Malware Detection", "Detect hidden payloads via Unicode variation selectors"},
		{"persistence-mechanisms", "Malware Detection", "Detect crontab, shell profile, systemd, git hook persistence"},
		{"reverse-shell", "Malware Detection", "Detect reverse shell establishment patterns"},
		{"blockchain-c2", "Malware Detection", "Detect blockchain-based C2 infrastructure"},
		{"ai-weaponization", "Malware Detection", "Detect AI CLI tool weaponization (s1ngularity)"},
		{"dead-mans-switch", "Malware Detection", "Detect conditional destruction payloads"},
		{"ci-backdoor", "Malware Detection", "Detect CI/CD pipeline backdoor injection"},
		{"socks-proxy", "Malware Detection", "Detect SOCKS proxy and network tunneling setup"},
		{"wasm-payload", "Malware Detection", "Detect WebAssembly-based payload delivery"},
		{"cryptominer", "Malware Detection", "Detect cryptocurrency mining software"},
	}
}
