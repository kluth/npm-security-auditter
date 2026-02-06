package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// ReproducibleBuildAnalyzer verifies build reproducibility signals:
// integrity hashes, registry signatures, attestations, and the ability
// to verify the published tarball against its source repository.
type ReproducibleBuildAnalyzer struct{}

func NewReproducibleBuildAnalyzer() *ReproducibleBuildAnalyzer {
	return &ReproducibleBuildAnalyzer{}
}

func (a *ReproducibleBuildAnalyzer) Name() string {
	return "reproducible-build"
}

func (a *ReproducibleBuildAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	// 1. Check integrity hash
	if version.Dist.Integrity == "" {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No integrity hash",
			Description: "Package distribution has no integrity hash (subresource integrity). This prevents verification that the downloaded tarball matches what was published.",
			Severity:    SeverityHigh,
			ExploitExample: "Without integrity verification:\n" +
				"    - MITM attacks can replace the tarball in transit\n" +
				"    - Registry compromises cannot be detected\n" +
				"    - npm cannot verify the package hasn't been tampered with\n" +
				"    Modern packages should include sha512 integrity hashes",
			Remediation: "Use packages that include integrity hashes. Report missing integrity to the maintainer.",
		})
	} else if strings.HasPrefix(version.Dist.Integrity, "sha1-") {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Weak integrity hash (SHA-1)",
			Description: fmt.Sprintf("Package uses SHA-1 integrity: %s. SHA-1 is cryptographically broken and should not be used for integrity verification.", truncate(version.Dist.Integrity, 40)),
			Severity:    SeverityMedium,
			ExploitExample: "SHA-1 collision attacks are practical since 2017:\n" +
				"    - SHAttered attack demonstrated SHA-1 collisions\n" +
				"    - An attacker could create a different tarball with the same SHA-1\n" +
				"    - Modern packages should use SHA-512",
			Remediation: "Request the maintainer to republish with SHA-512 integrity.",
		})
	}

	// 2. Check registry signatures
	if len(version.Dist.Signatures) == 0 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No registry signatures",
			Description: "Package has no npm registry signatures. Signatures allow verification that the package was published through the official registry.",
			Severity:    SeverityLow,
			ExploitExample: "Registry signatures provide provenance:\n" +
				"    - npm signs packages when they are published\n" +
				"    - Missing signatures may indicate the package was published\n" +
				"      before signature support or through unusual means\n" +
				"    - `npm audit signatures` can verify signed packages",
			Remediation: "Run `npm audit signatures` to verify package signatures. Consider using signed alternatives.",
		})
	}

	// 3. Check attestations (SLSA provenance)
	if version.Dist.Attestations == nil {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No build provenance attestation",
			Description: "Package has no SLSA provenance attestation. Attestations prove the package was built from a specific source commit in a specific CI environment.",
			Severity:    SeverityLow,
			ExploitExample: "Build provenance attestation (SLSA) proves:\n" +
				"    - Which source repo the package was built from\n" +
				"    - Which CI/CD pipeline ran the build\n" +
				"    - That the build was not tampered with\n" +
				"    npm supports provenance since npm v9.5.0",
			Remediation: "Prefer packages with provenance attestations. Run `npm audit signatures` to check.",
		})
	}

	// 4. Check ability to verify against source
	repo := version.Repository
	if repo == nil {
		repo = pkg.Repository
	}
	if repo == nil || repo.URL == "" {
		severity := SeverityMedium
		desc := "Package has no repository URL. Cannot verify the published code against source."
		if version.Dist.Attestations != nil {
			severity = SeverityLow
			desc += " Build attestations are present, which provides partial source verification."
		}
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No source verification possible",
			Description: desc,
			Severity:    severity,
			ExploitExample: "Without source verification:\n" +
				"    - Cannot compare published code against open source\n" +
				"    - Cannot detect if malicious code was injected during publishing\n" +
				"    - Must blindly trust the published tarball",
			Remediation: "Consider using an alternative package that provides source verification via a repository link.",
		})
	}

	return findings, nil
}
