package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// RemoteDepsAnalyzer detects remote/dynamic dependencies that pull code from
// URLs instead of the npm registry. This is the PhantomRaven attack vector.
type RemoteDepsAnalyzer struct{}

func NewRemoteDepsAnalyzer() *RemoteDepsAnalyzer {
	return &RemoteDepsAnalyzer{}
}

func (a *RemoteDepsAnalyzer) Name() string {
	return "remote-dependencies"
}

// githubShorthandPattern matches "user/repo" or "user/repo#branch" format.
var githubShorthandPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+(?:#.+)?$`)

func (a *RemoteDepsAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	findings = append(findings, a.checkDeps(version.Dependencies, "dependencies")...)
	findings = append(findings, a.checkDeps(version.DevDependencies, "devDependencies")...)

	return findings, nil
}

func (a *RemoteDepsAnalyzer) checkDeps(deps map[string]string, depType string) []Finding {
	var findings []Finding

	for name, version := range deps {
		vLower := strings.ToLower(version)

		// HTTP URL dependency (most dangerous - unencrypted)
		if strings.HasPrefix(vLower, "http://") {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("HTTP URL dependency: %s", name),
				Description: fmt.Sprintf("Dependency %q in %s resolves to an unencrypted HTTP URL: %s", name, depType, version),
				Severity:    SeverityCritical,
				ExploitExample: "HTTP URL dependencies bypass the npm registry entirely:\n" +
					"    1. The package is downloaded from the URL, not from npmjs.com\n" +
					"    2. HTTP is unencrypted, allowing MITM attacks to inject code\n" +
					"    3. The URL can serve different code at different times\n" +
					"    4. npm audit and vulnerability scanners cannot detect this\n" +
					"    PhantomRaven attack: attacker controls the URL and serves malware",
				Remediation: "Replace URL dependencies with versioned npm packages. Never use HTTP URLs.",
			})
			continue
		}

		// HTTPS URL dependency (safer but still bypasses registry)
		if strings.HasPrefix(vLower, "https://") {
			severity := SeverityHigh
			desc := fmt.Sprintf("Dependency %q in %s resolves to an HTTPS URL: %s", name, depType, version)
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("HTTPS URL dependency: %s", name),
				Description: desc,
				Severity:    severity,
				ExploitExample: "URL dependencies bypass the npm registry:\n" +
					"    - The URL can serve different code at any time\n" +
					"    - No version pinning or integrity checking\n" +
					"    - npm audit cannot scan the dependency\n" +
					"    - If the URL server is compromised, so is your project",
				Remediation: "Replace URL dependencies with versioned npm packages published to the registry.",
			})
			continue
		}

		// Git URL dependency
		if strings.HasPrefix(vLower, "git+") || strings.HasPrefix(vLower, "git://") {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("Git URL dependency: %s", name),
				Description: fmt.Sprintf("Dependency %q in %s resolves to a Git repository: %s", name, depType, version),
				Severity:    SeverityMedium,
				ExploitExample: "Git dependencies can change without version updates:\n" +
					"    - Branch references can point to different commits\n" +
					"    - Repository can be force-pushed with malicious code\n" +
					"    - No integrity hash verification like npm packages",
				Remediation: "If using Git dependencies, pin to a specific commit hash. Prefer published npm packages.",
			})
			continue
		}

		// GitHub shorthand (user/repo)
		if githubShorthandPattern.MatchString(version) && !strings.Contains(version, "@") {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("GitHub shorthand dependency: %s", name),
				Description: fmt.Sprintf("Dependency %q in %s uses GitHub shorthand: %s", name, depType, version),
				Severity:    SeverityMedium,
				ExploitExample: "GitHub shorthand resolves to a GitHub tarball:\n" +
					"    - Points to the default branch, which can change\n" +
					"    - No integrity verification\n" +
					"    - Repository can be transferred or compromised",
				Remediation: "Use a published npm package with version pinning instead of GitHub shorthand.",
			})
			continue
		}

		// file: dependency (suspicious in published packages)
		if strings.HasPrefix(vLower, "file:") {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("Local file dependency: %s", name),
				Description: fmt.Sprintf("Dependency %q in %s uses a local file path: %s. This is invalid in published packages.", name, depType, version),
				Severity:    SeverityHigh,
				ExploitExample: "file: dependencies in published packages are suspicious:\n" +
					"    - They reference paths on the publisher's machine\n" +
					"    - npm may resolve them unexpectedly at install time\n" +
					"    - Could indicate a misconfigured or tampered package",
				Remediation: "This dependency should reference a published npm package, not a local file path.",
			})
			continue
		}
	}

	return findings
}
