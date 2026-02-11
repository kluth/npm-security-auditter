package analyzer

import (
	"context"
	"fmt"
	"regexp"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

type ShellScriptAnalyzer struct{}

func NewShellScriptAnalyzer() *ShellScriptAnalyzer {
	return &ShellScriptAnalyzer{}
}

func (a *ShellScriptAnalyzer) Name() string {
	return "dangerous-shell-scripts"
}

var (
	shellPatterns = []struct {
		pattern  *regexp.Regexp
		severity Severity
		title    string
		desc     string
	}{
		{
			regexp.MustCompile(`(curl|wget)\s+.*\|\s*(bash|sh|zsh|python|perl|php|node)`),
			SeverityCritical,
			"Dangerous shell command detected",
			"The script appears to download and immediately execute remote code.",
		},
		{
			regexp.MustCompile(`rm\s+(-r[f]?|-f[r]?)\s+(/|~|\$HOME|\$ROOT)`),
			SeverityHigh,
			"Dangerous shell command detected",
			"The script attempts to delete critical system directories.",
		},
		{
			regexp.MustCompile(`\bsudo\b`),
			SeverityHigh,
			"Privilege escalation attempt",
			"The script uses 'sudo', which is highly suspicious in npm packages and breaks non-interactive installs.",
		},
		{
			regexp.MustCompile(`>\s*/dev/null`),
			SeverityMedium,
			"Obfuscated/Silent execution",
			"The script suppresses output to /dev/null, often used to hide malicious activities.",
		},
		{
			regexp.MustCompile(`base64\s+-d`),
			SeverityMedium,
			"Base64 decoding in shell",
			"The script decodes base64 data, which is a common technique to hide payloads.",
		},
	}
)

func (a *ShellScriptAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	for scriptName, scriptContent := range version.Scripts {
		for _, pat := range shellPatterns {
			if pat.pattern.MatchString(scriptContent) {
				findings = append(findings, Finding{
					Analyzer:       a.Name(),
					Title:          pat.title,
					Description:    fmt.Sprintf("Script %q contains suspicious shell commands: %s", scriptName, pat.desc),
					Severity:       pat.severity,
					ExploitExample: fmt.Sprintf("In package.json: \"%s\": \"%s\"", scriptName, scriptContent),
					Remediation:    "Remove dangerous lifecycle scripts or use --ignore-scripts during installation. Audit all scripts that download and execute remote content.",
				})
			}
		}
	}

	return findings, nil
}
