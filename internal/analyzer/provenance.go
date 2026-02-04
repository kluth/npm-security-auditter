package analyzer

import (
	"context"
	"strings"

	"github.com/matthias/auditter/internal/registry"
)

// ProvenanceAnalyzer checks for supply chain and provenance signals.
type ProvenanceAnalyzer struct{}

func NewProvenanceAnalyzer() *ProvenanceAnalyzer { return &ProvenanceAnalyzer{} }

func (p *ProvenanceAnalyzer) Name() string { return "provenance" }

func (p *ProvenanceAnalyzer) Analyze(_ context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	// Check for npm signatures
	if len(version.Dist.Signatures) == 0 {
		findings = append(findings, Finding{
			Analyzer:    p.Name(),
			Title:       "No registry signatures",
			Description: "Package version has no npm registry signatures",
			Severity:    SeverityLow,
			                        ExploitExample: "Without registry signatures, tarball integrity cannot be verified:\n" +
			                                "    - An attacker with registry/CDN access could swap the tarball\n" +
			                                "    - npm signatures prove the registry published this exact artifact\n" +
			                                "    - Check: npm audit signatures",
			                        Remediation: "Verify the registry signatures using 'npm audit signatures'. Packages without signatures should be treated with caution, especially if they are recently updated.",
			                })
			
	}

	// Check for provenance attestations
	if version.Dist.Attestations == nil {
		findings = append(findings, Finding{
			Analyzer:    p.Name(),
			Title:       "No provenance attestation",
			Description: "Package has no build provenance attestation. Cannot verify the source of the build.",
			Severity:    SeverityLow,
			                        ExploitExample: "Without provenance, there is no link between source code and published artifact:\n" +
			                                "    - Maintainer's machine could be compromised, injecting code at publish time\n" +
			                                "    - No proof the tarball was built from the repository's source\n" +
			                                "    - Provenance (SLSA) proves: built by GitHub Actions from commit X of repo Y\n" +
			                                "    - Check: npm audit signatures --registry https://registry.npmjs.org",
			                        Remediation: "Prefer packages with build provenance. For critical dependencies, manually verify that the published tarball matches the source code in the repository.",
			                })
			
	}

	// Check integrity hash
	if version.Dist.Integrity == "" && version.Dist.Shasum == "" {
		findings = append(findings, Finding{
			Analyzer:    p.Name(),
			Title:       "No integrity hash",
			Description: "Package version has no integrity hash (shasum or integrity field)",
			Severity:    SeverityHigh,
			                        ExploitExample: "Without integrity hashes, the tarball can be tampered with undetected:\n" +
			                                "    - Man-in-the-middle attacks can modify the package during download\n" +
			                                "    - Registry compromise can swap package contents silently\n" +
			                                "    - npm normally verifies integrity — its absence is highly anomalous\n" +
			                                "    - This should almost never happen on the public npm registry",
			                        Remediation: "This is a critical anomaly. Do not install this package version and report it to the npm registry security team.",
			                })
			
	}

	// Check that repository link exists and is consistent
	p.checkRepoConsistency(pkg, version, &findings)

	return findings, nil
}

func (p *ProvenanceAnalyzer) checkRepoConsistency(pkg *registry.PackageMetadata, version *registry.PackageVersion, findings *[]Finding) {
	pkgRepo := ""
	if pkg.Repository != nil {
		pkgRepo = normalizeRepoURL(pkg.Repository.URL)
	}

	verRepo := ""
	if version.Repository != nil {
		verRepo = normalizeRepoURL(version.Repository.URL)
	}

	if pkgRepo == "" && verRepo == "" {
		*findings = append(*findings, Finding{
			Analyzer:    p.Name(),
			Title:       "No source repository link",
			Description: "Package has no linked source repository, making source verification impossible",
			Severity:    SeverityMedium,
			                        ExploitExample: "No source repository makes it impossible to verify what you're installing:\n" +
			                                "    - Cannot compare published tarball to source code\n" +
			                                "    - Cannot review commit history for suspicious changes\n" +
			                                "    - Attacker publishes code with no audit trail\n" +
			                                "    - Inspect manually: npm pack <pkg> && tar -xzf *.tgz && cat package/*",
			                        Remediation: "Exercise extreme caution. Manually audit the package content using 'npm pack' before use.",
			                })
			
		return
	}

	// If both are set, check consistency
	if pkgRepo != "" && verRepo != "" && pkgRepo != verRepo {
		*findings = append(*findings, Finding{
			Analyzer:    p.Name(),
			Title:       "Repository URL mismatch",
			Description: "Package-level and version-level repository URLs differ, which may indicate a supply chain issue",
			Severity:    SeverityHigh,
			                        ExploitExample: "Repository URL mismatch is a strong indicator of package hijacking:\n" +
			                                "    - Original package pointed to github.com/original-author/pkg\n" +
			                                "    - New version points to github.com/attacker/pkg (or no repo)\n" +
			                                "    - Attacker took over publishing rights and changed the repo link\n" +
			                                "    - Compare the two repos to identify what changed and when",
			                        Remediation: "Manually verify the correct repository for the package. This mismatch often indicates that the package has been hijacked or the maintainer account compromised.",
			                })
			
	}
}

func normalizeRepoURL(url string) string {
	url = strings.ToLower(url)
	url = strings.TrimPrefix(url, "git+")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")
	return url
}
