package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/tarball"
)

type LockfileAnalyzer struct {
	trustedRegistries []string
}

func NewLockfileAnalyzer() *LockfileAnalyzer {
	return &LockfileAnalyzer{
		trustedRegistries: []string{
			"registry.npmjs.org",
			"registry.yarnpkg.com",
			"github.com",
			"codeload.github.com",
		},
	}
}

func (a *LockfileAnalyzer) Name() string {
	return "lockfile-analysis"
}

// Analyze is the main entry point, but we typically use AnalyzePackage for local tarballs
func (a *LockfileAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	return nil, nil
}

// AnalyzePackage scans the extracted package for lockfiles
func (a *LockfileAnalyzer) AnalyzePackage(ctx context.Context, ep *tarball.ExtractedPackage) ([]Finding, error) {
	var findings []Finding

	for _, f := range ep.Files {
		if filepath.Base(f.Path) == "package-lock.json" {
			content, err := os.ReadFile(filepath.Join(ep.Dir, f.Path))
			if err != nil {
				continue
			}
			findings = append(findings, a.scanLockfile(content)...)
		}
	}
	return findings, nil
}

// scanLockfile parses and checks a package-lock.json buffer
func (a *LockfileAnalyzer) scanLockfile(content []byte) []Finding {
	var findings []Finding
	var lockfile struct {
		Dependencies map[string]interface{} `json:"dependencies"`
		Packages     map[string]interface{} `json:"packages"` // npm v7+
	}

	if err := json.Unmarshal(content, &lockfile); err != nil {
		return nil
	}

	// Helper to check a dependency entry
	checkDep := func(name string, depData map[string]interface{}) {
		resolved, _ := depData["resolved"].(string)
		if resolved == "" {
			return
		}

		// Check Protocol
		if strings.HasPrefix(resolved, "http://") {
			findings = append(findings, Finding{
				Analyzer:       a.Name(),
				Title:          "Insecure HTTP registry URL",
				Description:    fmt.Sprintf("Dependency %q uses an insecure HTTP URL: %s", name, resolved),
				Severity:       SeverityMedium,
				ExploitExample: fmt.Sprintf(`"resolved": "%s"`, resolved),
				Remediation:    "Update the lockfile to use HTTPS to prevent Man-in-the-Middle attacks modifying code during install.",
			})
		}

		// Check Trusted Registry
		isTrusted := false
		for _, trusted := range a.trustedRegistries {
			if strings.Contains(resolved, trusted) {
				isTrusted = true
				break
			}
		}

		// Allow relative paths (file:) or standard git protocols if they match expected patterns
		if !isTrusted && strings.HasPrefix(resolved, "http") {
			findings = append(findings, Finding{
				Analyzer:       a.Name(),
				Title:          "Suspicious lockfile registry URL",
				Description:    fmt.Sprintf("Dependency %q resolves to an untrusted domain: %s", name, resolved),
				Severity:       SeverityCritical,
				ExploitExample: fmt.Sprintf(`"resolved": "%s"`, resolved),
				Remediation:    "Verify why this dependency is being fetched from a non-standard registry. This is a common supply chain attack vector.",
			})
		}
	}

	// Scan 'dependencies' (npm v1/v2/v3 lockfiles)
	for name, data := range lockfile.Dependencies {
		if depMap, ok := data.(map[string]interface{}); ok {
			checkDep(name, depMap)
		}
	}

	// Scan 'packages' (npm v7+ lockfiles)
	for name, data := range lockfile.Packages {
		if name == "" {
			continue
		} // Root package
		if depMap, ok := data.(map[string]interface{}); ok {
			checkDep(name, depMap)
		}
	}

	return findings
}
