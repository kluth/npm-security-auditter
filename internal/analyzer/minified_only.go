package analyzer

import (
	"context"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/tarball"
)

type MinifiedOnlyAnalyzer struct{}

func NewMinifiedOnlyAnalyzer() *MinifiedOnlyAnalyzer {
	return &MinifiedOnlyAnalyzer{}
}

func (a *MinifiedOnlyAnalyzer) Name() string {
	return "minified-only"
}

func (a *MinifiedOnlyAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	return nil, nil
}

func (a *MinifiedOnlyAnalyzer) AnalyzePackage(ctx context.Context, ep *tarball.ExtractedPackage) ([]Finding, error) {
	var findings []Finding

	jsFiles := 0
	minifiedFiles := 0

	for _, f := range ep.Files {
		if !f.IsJS {
			continue
		}
		jsFiles++

		isMin := strings.Contains(f.Path, ".min.") ||
			strings.Contains(f.Path, "/dist/") ||
			strings.Contains(f.Path, "/build/") ||
			strings.Contains(f.Path, "/bundle")

		if isMin {
			minifiedFiles++
		}
	}

	// If we have JS files and ALL of them look like minified/distribution files
	if jsFiles > 0 && jsFiles == minifiedFiles {
		findings = append(findings, Finding{
			Analyzer:       a.Name(),
			Title:          "Package contains only minified/obfuscated code",
			Description:    "All JavaScript files in this package appear to be minified or bundled distribution files. Published source code is missing, which is a common technique to hide malicious behavior.",
			Severity:       SeverityMedium,
			ExploitExample: "// Obfuscated code sample\nvar _0x5a2e=['\x68\x65\x6c\x6c\x6f','\x77\x6f\x72\x6c\x64'];...",
			Remediation:    "Check the associated source repository (e.g., GitHub) to see if the source code matches the distributed bundle. Avoid packages that don't provide source code.",
		})
	}

	return findings, nil
}
