package analyzer

import (
	"context"
	"fmt"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// ManifestConfusionAnalyzer detects discrepancies between registry manifest
// and tarball package.json that indicate manifest confusion attacks.
// See: https://blog.vlt.sh/blog/the-massive-hole-in-the-npm-ecosystem
type ManifestConfusionAnalyzer struct{}

func NewManifestConfusionAnalyzer() *ManifestConfusionAnalyzer {
	return &ManifestConfusionAnalyzer{}
}

func (a *ManifestConfusionAnalyzer) Name() string {
	return "manifest-confusion"
}

// dangerousLifecycleScripts are scripts that execute automatically on install.
var dangerousLifecycleScripts = []string{
	"preinstall", "install", "postinstall",
	"preuninstall", "postuninstall",
	"prepublish", "prepare",
}

func (a *ManifestConfusionAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	// The actual manifest comparison is done by tarball.go's comparePackageJSON.
	// This analyzer provides the AnalyzeManifest method for deeper analysis
	// when both manifests are available.
	return nil, nil
}

// AnalyzeManifest compares tarball package.json fields against registry manifest.
func (a *ManifestConfusionAnalyzer) AnalyzeManifest(
	tarballScripts, registryScripts map[string]string,
	tarballDeps, registryDeps map[string]string,
	tarballName, registryName string,
) ([]Finding, error) {
	var findings []Finding

	// 1. Package name mismatch
	if tarballName != "" && registryName != "" && tarballName != registryName {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Manifest confusion: package name mismatch",
			Description: fmt.Sprintf("Tarball package.json name %q differs from registry manifest name %q. This is a strong indicator of a manifest confusion attack.", tarballName, registryName),
			Severity:    SeverityCritical,
			ExploitExample: "Manifest confusion allows attackers to publish a tarball with different metadata:\n" +
				"    1. npm registry only validates the 'publish' manifest, not the tarball\n" +
				"    2. Attacker publishes with clean manifest but malicious tarball\n" +
				"    3. `npm view` shows clean scripts, but `npm install` runs malicious ones\n" +
				"    4. Even `npm audit` cannot detect this discrepancy",
			Remediation: "Do NOT install this package. Report it to npm security team.",
		})
	}

	// 2. Hidden lifecycle scripts (in tarball but not in registry)
	for _, scriptName := range dangerousLifecycleScripts {
		tarballScript, inTarball := tarballScripts[scriptName]
		_, inRegistry := registryScripts[scriptName]

		if inTarball && !inRegistry {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("Manifest confusion: hidden %s script", scriptName),
				Description: fmt.Sprintf("Tarball contains %q script not visible in registry: %s", scriptName, truncate(tarballScript, 100)),
				Severity:    SeverityCritical,
				ExploitExample: fmt.Sprintf("The %s script is hidden from registry browsing:\n", scriptName) +
					"    - `npm view <pkg> scripts` shows NO install scripts\n" +
					"    - But `npm install` WILL execute the hidden script\n" +
					"    - The script runs: " + truncate(tarballScript, 80),
				Remediation: "This package uses manifest confusion to hide install scripts. Do NOT install it. Report to npm security.",
			})
		}
	}

	// 3. Modified lifecycle scripts (different content in tarball vs registry)
	for _, scriptName := range dangerousLifecycleScripts {
		tarballScript, inTarball := tarballScripts[scriptName]
		registryScript, inRegistry := registryScripts[scriptName]

		if inTarball && inRegistry && tarballScript != registryScript {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("Manifest confusion: modified %s script", scriptName),
				Description: fmt.Sprintf("Tarball %q script differs from registry. Registry: %q, Tarball: %q", scriptName, truncate(registryScript, 60), truncate(tarballScript, 60)),
				Severity:    SeverityHigh,
				ExploitExample: "Script content mismatch between registry and tarball:\n" +
					"    - Registry shows a benign script\n" +
					"    - Tarball contains a different, potentially malicious script\n" +
					"    - npm installs the tarball version, not the registry version",
				Remediation: "Inspect both versions of the script. The tarball version is what actually executes.",
			})
		}
	}

	// 4. Hidden dependencies
	for dep, ver := range tarballDeps {
		if _, ok := registryDeps[dep]; !ok {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("Manifest confusion: hidden dependency %q", dep),
				Description: fmt.Sprintf("Tarball lists dependency %s@%s not in registry manifest.", dep, ver),
				Severity:    SeverityHigh,
				ExploitExample: "Hidden dependencies are installed but invisible:\n" +
					"    - `npm view <pkg> dependencies` does not show them\n" +
					"    - They are still installed during `npm install`\n" +
					"    - Attacker can inject a malicious dependency this way",
				Remediation: "Inspect the hidden dependency. It may contain malicious code that executes on install.",
			})
		}
	}

	return findings, nil
}
