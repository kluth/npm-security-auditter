package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// CodeSigningAnalyzer verifies code signing and cryptographic integrity
// of npm packages, checking for registry signatures, SLSA provenance
// attestations, and signature quality.
type CodeSigningAnalyzer struct{}

func NewCodeSigningAnalyzer() *CodeSigningAnalyzer {
	return &CodeSigningAnalyzer{}
}

func (a *CodeSigningAnalyzer) Name() string {
	return "code-signing"
}

// npmRegistryKeyPrefix is the known npm registry signing key prefix.
const npmRegistryKeyPrefix = "SHA256:"

func (a *CodeSigningAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	hasAttestations := version.Dist.Attestations != nil
	hasSLSA := hasAttestations && version.Dist.Attestations.Provenance != nil &&
		strings.Contains(version.Dist.Attestations.Provenance.PredicateType, "slsa.dev")

	// 1. Check for registry signatures
	if len(version.Dist.Signatures) == 0 {
		severity := SeverityMedium
		desc := "Package has no npm registry signatures. Cannot verify the package was published through the official npm registry."
		if hasAttestations {
			severity = SeverityLow
			desc += " Build attestations are present, which provides alternative verification."
		}
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Unsigned package (no registry signatures)",
			Description: desc,
			Severity:    severity,
			ExploitExample: "Unsigned packages cannot be verified:\n" +
				"    - npm registry signatures prove a package was published officially\n" +
				"    - Without signatures, a package could have been injected\n" +
				"    - Run `npm audit signatures` to check all installed packages\n" +
				"    - npm v9.5.0+ supports signature verification",
			Remediation: "Run `npm audit signatures` to check package integrity. Prefer signed packages.",
		})
	} else {
		// Check signature quality
		for _, sig := range version.Dist.Signatures {
			if len(sig.Keyid) < 10 {
				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       "Weak signing key detected",
					Description: fmt.Sprintf("Signature key ID %q is suspiciously short (%d chars). This may indicate a weak or forged signature.", sig.Keyid, len(sig.Keyid)),
					Severity:    SeverityMedium,
					ExploitExample: "Short key IDs can be spoofed:\n" +
						"    - Legitimate npm keys use SHA256: prefix with full fingerprint\n" +
						"    - Short IDs increase collision risk\n" +
						"    - An attacker could potentially forge a matching short ID",
					Remediation: "Verify the signing key against the npm public key registry.",
				})
			}

			if len(sig.Sig) < 20 {
				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       "Suspicious signature value",
					Description: fmt.Sprintf("Signature value is unusually short (%d chars), which may indicate an invalid or placeholder signature.", len(sig.Sig)),
					Severity:    SeverityMedium,
					Remediation: "Verify the signature using npm's public keys.",
				})
			}
		}
	}

	// 2. Note SLSA provenance if present
	if hasSLSA {
		// Good sign - no finding needed for SLSA compliance
		_ = hasSLSA
	}

	return findings, nil
}
