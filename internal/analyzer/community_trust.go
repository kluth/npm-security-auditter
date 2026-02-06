package analyzer

import (
	"context"
	"fmt"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// CommunityTrustAnalyzer evaluates open source integrity signals:
// repository presence, license, documentation, maintainer diversity,
// and community engagement indicators.
type CommunityTrustAnalyzer struct{}

func NewCommunityTrustAnalyzer() *CommunityTrustAnalyzer {
	return &CommunityTrustAnalyzer{}
}

func (a *CommunityTrustAnalyzer) Name() string {
	return "community-trust"
}

func (a *CommunityTrustAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	// 1. No repository URL
	repo := version.Repository
	if repo == nil {
		repo = pkg.Repository
	}
	if repo == nil || repo.URL == "" {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No repository URL",
			Description: "Package does not specify a source code repository. This prevents code verification and community oversight.",
			Severity:    SeverityMedium,
			ExploitExample: "Missing repository hinders verification:\n" +
				"    - Cannot compare published code against source\n" +
				"    - Cannot check commit history for suspicious changes\n" +
				"    - Cannot verify the maintainer's identity\n" +
				"    - Legitimate packages almost always link to their source",
			Remediation: "Look for the source code independently. Be cautious with packages that hide their source.",
		})
	}

	// 2. No license
	license := version.License
	if license == "" {
		license = pkg.License
	}
	if license == "" {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No license specified",
			Description: "Package has no license field. This is unusual for legitimate open source packages and may indicate a hastily published malicious package.",
			Severity:    SeverityMedium,
			ExploitExample: "Missing license is a red flag:\n" +
				"    - Legitimate packages specify a license (MIT, Apache, ISC, etc.)\n" +
				"    - Malicious packages often skip metadata fields\n" +
				"    - No license means the code is technically all-rights-reserved",
			Remediation: "Contact the maintainer about licensing. Consider using a licensed alternative.",
		})
	}

	// 3. No description
	desc := version.Description
	if desc == "" {
		desc = pkg.Description
	}
	if desc == "" {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No package description",
			Description: "Package has no description. Legitimate packages typically describe their purpose.",
			Severity:    SeverityLow,
			ExploitExample: "Missing description is common in malicious packages:\n" +
				"    - Attackers focus on the payload, not documentation\n" +
				"    - Typosquat packages often lack proper metadata\n" +
				"    - Description is one of the first things reviewers check",
			Remediation: "Inspect the package contents directly to understand its purpose.",
		})
	}

	// 4. No README or very short README
	if len(pkg.Readme) == 0 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No README documentation",
			Description: "Package has no README file. This is a strong indicator of a low-quality or malicious package.",
			Severity:    SeverityMedium,
			ExploitExample: "Missing README correlates strongly with malicious packages:\n" +
				"    - 89% of malicious npm packages lack proper documentation\n" +
				"    - Legitimate maintainers document their packages\n" +
				"    - Missing README makes the package purpose opaque",
			Remediation: "Be extremely cautious with undocumented packages. Review the source code directly.",
		})
	} else if len(pkg.Readme) < 50 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Minimal README documentation",
			Description: fmt.Sprintf("Package README is only %d characters long. This may indicate a low-effort or malicious package.", len(pkg.Readme)),
			Severity:    SeverityLow,
			Remediation: "Review the source code. A minimal README may indicate the package was created hastily.",
		})
	}

	// 5. Single maintainer on established package (bus factor risk)
	if len(pkg.Maintainers) == 1 && len(pkg.Versions) > 5 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Single maintainer (bus factor risk)",
			Description: fmt.Sprintf("Package has %d versions but only one maintainer (%s). If this account is compromised, the entire package supply chain is at risk.", len(pkg.Versions), pkg.Maintainers[0].Name),
			Severity:    SeverityLow,
			ExploitExample: "Single maintainer risks:\n" +
				"    - Account compromise = full control of the package\n" +
				"    - event-stream attack exploited a single tired maintainer\n" +
				"    - No code review from other maintainers\n" +
				"    - Higher risk of social engineering attacks",
			Remediation: "Pin to specific versions. Monitor for unexpected updates. Consider the account takeover risk.",
		})
	}

	// 6. No maintainers listed at all
	if len(pkg.Maintainers) == 0 && len(version.Maintainers) == 0 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No maintainers listed",
			Description: "Package has no maintainer information. This is very unusual and suspicious.",
			Severity:    SeverityHigh,
			ExploitExample: "Missing maintainer information prevents:\n" +
				"    - Accountability for package contents\n" +
				"    - Contacting the author about security issues\n" +
				"    - Verifying the package's legitimacy",
			Remediation: "Do not use packages without identifiable maintainers.",
		})
	}

	return findings, nil
}
