package analyzer

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/tarball"
)

type DangerousExtensionAnalyzer struct{}

func NewDangerousExtensionAnalyzer() *DangerousExtensionAnalyzer {
	return &DangerousExtensionAnalyzer{}
}

func (a *DangerousExtensionAnalyzer) Name() string {
	return "dangerous-extensions"
}

func (a *DangerousExtensionAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	return nil, nil
}

func (a *DangerousExtensionAnalyzer) AnalyzePackage(ctx context.Context, ep *tarball.ExtractedPackage) ([]Finding, error) {
	var findings []Finding

	for _, f := range ep.Files {
		ext := strings.ToLower(filepath.Ext(f.Path))

		switch ext {
		case ".exe", ".dll", ".so", ".dylib":
			findings = append(findings, Finding{
				Analyzer:       a.Name(),
				Title:          "Dangerous file extension detected",
				Description:    fmt.Sprintf("File %q has a binary executable extension (%s).", f.Path, ext),
				Severity:       SeverityCritical,
				ExploitExample: fmt.Sprintf("// Execution via native call or child_process\nrequire('child_process').execFile('./%s');", f.Path),
				Remediation:    "Binaries should not be part of npm packages unless they are platform-specific native addons (node-gyp). Manually verify the purpose of these files.",
			})
		case ".sh", ".bat", ".cmd", ".ps1", ".vbs":
			findings = append(findings, Finding{
				Analyzer:       a.Name(),
				Title:          "Dangerous file extension detected",
				Description:    fmt.Sprintf("File %q is a shell script (%s) which can execute arbitrary commands.", f.Path, ext),
				Severity:       SeverityHigh,
				ExploitExample: fmt.Sprintf("// Execution via postinstall\n\"scripts\": { \"postinstall\": \"./%s\" }", f.Path),
				Remediation:    "Audit the content of shell scripts. They are frequently used to download malware or exfiltrate environment variables.",
			})
		case ".py", ".pl", ".rb", ".php", ".jar":
			findings = append(findings, Finding{
				Analyzer:       a.Name(),
				Title:          "Suspicious file extension detected",
				Description:    fmt.Sprintf("File %q has a non-JS scripting extension (%s), unusual for npm packages.", f.Path, ext),
				Severity:       SeverityMedium,
				ExploitExample: fmt.Sprintf("// Execution via child_process\nrequire('child_process').exec('python ./%s');", f.Path),
				Remediation:    "Check why non-JS code is bundled. It might be a tool used by a build script, or a payload for an existing system interpreter.",
			})
		}
	}

	return findings, nil
}
