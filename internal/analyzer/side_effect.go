package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

var (
	// Suspicious calls that shouldn't typically be at the top level
	sideEffectPatterns = map[*regexp.Regexp]Severity{
		regexp.MustCompile(`^(?:const\s+\w+\s*=\s*)?require\(['"]child_process['"]\)\.(?:exec|spawn|fork)`): SeverityCritical,
		regexp.MustCompile(`^(?:await\s+)?fetch\(['"]https?://`):                                            SeverityHigh,
		regexp.MustCompile(`^(?:const\s+\w+\s*=\s*)?require\(['"]fs['"]\)\.(?:writeFile|appendFile|rm)`):    SeverityHigh,
		regexp.MustCompile(`^eval\(`): SeverityHigh,
	}
)

type SideEffectAnalyzer struct{}

func NewSideEffectAnalyzer() *SideEffectAnalyzer {
	return &SideEffectAnalyzer{}
}

func (a *SideEffectAnalyzer) Name() string {
	return "side-effects"
}

func (a *SideEffectAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	return nil, nil
}

func (a *SideEffectAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Heuristic: If the line is NOT indented, it's more likely to be a top-level statement
		// We check if the original line starts with the trimmed version (meaning no leading whitespace)
		if strings.HasPrefix(line, trimmed) {
			for pattern, severity := range sideEffectPatterns {
				if pattern.MatchString(trimmed) {
					findings = append(findings, Finding{
						Analyzer:       a.Name(),
						Title:          "Immediate code execution detected",
						Description:    "The package contains potentially dangerous code that executes immediately when the module is imported in " + filename,
						Severity:       severity,
						ExploitExample: "// Executed immediately on require('package')\n" + trimmed,
						Remediation:    "Move side effects into explicit initialization functions that the user must call. Avoid top-level network or process calls.",
					})
					break
				}
			}
		}
	}

	return findings
}
