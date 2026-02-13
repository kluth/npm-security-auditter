package analyzer

import (
	"fmt"
	"regexp"
)

// CIBackdoorAnalyzer detects GitHub Actions workflow injection and CI/CD
// pipeline backdooring. Based on Shai-Hulud which created unauthorized
// GitHub Actions workflows in compromised repositories to exfiltrate
// secrets and maintain persistence across code changes.
type CIBackdoorAnalyzer struct{}

func NewCIBackdoorAnalyzer() *CIBackdoorAnalyzer {
	return &CIBackdoorAnalyzer{}
}

func (a *CIBackdoorAnalyzer) Name() string {
	return "ci-backdoor"
}

var ciBackdoorPatterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// GitHub Actions workflow file creation
	{
		regexp.MustCompile(`\.github/workflows/`),
		"GitHub Actions workflow manipulation",
		"Code references GitHub Actions workflow directory, potentially creating or modifying CI/CD pipelines",
		SeverityHigh,
	},
	// Secrets access in dynamically generated content
	{
		regexp.MustCompile(`(?i)secrets\.\w+[\s\S]{0,100}(?:writeFile|appendFile|echo|>>)`),
		"CI secrets exfiltration setup",
		"Code accesses CI secrets and writes them to files, a workflow secret exfiltration technique",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`\$\{\{\s*secrets\.\w+\s*\}\}`),
		"GitHub Actions secrets reference",
		"Code contains GitHub Actions secrets interpolation syntax, suspicious outside of workflow files",
		SeverityHigh,
	},
	// CI environment variable targeting
	{
		regexp.MustCompile(`ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|ACTIONS_CACHE_URL`),
		"GitHub Actions runtime token access",
		"Code targets GitHub Actions runtime tokens which provide access to CI infrastructure and artifact storage",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`GITHUB_TOKEN[\s\S]{0,100}(?:fetch|curl|wget|http|https|request)`),
		"GITHUB_TOKEN exfiltration",
		"Code uses GITHUB_TOKEN for network requests, potentially exfiltrating CI credentials",
		SeverityCritical,
	},
	// Workflow_dispatch / repository_dispatch triggers
	{
		regexp.MustCompile(`workflow_dispatch|repository_dispatch`),
		"Remote workflow trigger",
		"Code references remote workflow trigger events, enabling attackers to invoke CI pipelines on demand",
		SeverityMedium,
	},
	// Malicious GitHub Actions references
	{
		regexp.MustCompile(`uses:\s*[^/]+/[^@]+@[a-f0-9]{40}`),
		"GitHub Action pinned to commit hash",
		"Workflow references an action by commit hash rather than version tag. While this can be a security best practice, it can also pin to a specific malicious commit",
		SeverityLow,
	},
	// CI/CD pipeline file manipulation
	{
		regexp.MustCompile(`(?i)\.gitlab-ci\.yml|\.circleci/config|Jenkinsfile|\.travis\.yml|azure-pipelines\.yml`),
		"CI/CD pipeline file manipulation",
		"Code references CI/CD configuration files from multiple providers, indicating broad pipeline targeting",
		SeverityHigh,
	},
	// Actions/checkout + curl pattern
	{
		regexp.MustCompile(`actions/checkout[\s\S]{0,300}(?:curl|wget)\s+.*\|.*(?:bash|sh)`),
		"Checkout + remote script execution",
		"Workflow checks out code then downloads and executes a remote script, a common CI backdoor pattern",
		SeverityCritical,
	},
}

func (a *CIBackdoorAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range ciBackdoorPatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "CI/CD backdoor injection (Shai-Hulud worm, September 2025):\n" +
					"    1. Worm creates .github/workflows/update.yml in compromised repos\n" +
					"    2. Workflow runs on every push, exfiltrating ${{ secrets.* }}\n" +
					"    3. GITHUB_TOKEN used to create more infected repositories\n" +
					"    4. Backdoor persists across code changes and package removals\n" +
					"    Impact: 25,000 malicious GitHub repository forks created",
				Remediation: "Review all CI/CD workflow files for unauthorized modifications. Rotate CI secrets immediately. Audit GitHub Actions workflow runs for unexpected executions.",
			})
		}
	}

	return findings
}
