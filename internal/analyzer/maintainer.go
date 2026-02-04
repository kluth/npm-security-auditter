package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// MaintainerAnalyzer checks maintainer/ownership risks.
type MaintainerAnalyzer struct{}

func NewMaintainerAnalyzer() *MaintainerAnalyzer { return &MaintainerAnalyzer{} }

func (m *MaintainerAnalyzer) Name() string { return "maintainers" }

// suspiciousEmailDomains are free email domains that may indicate less accountability.
var suspiciousEmailDomains = []string{
	"mailinator.com", "guerrillamail.com", "tempmail.com",
	"throwaway.email", "yopmail.com", "sharklasers.com",
}

func (m *MaintainerAnalyzer) Analyze(_ context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	// Check number of maintainers
	maintainers := pkg.Maintainers
	if len(version.Maintainers) > 0 {
		maintainers = version.Maintainers
	}

	if len(maintainers) == 0 {
		findings = append(findings, Finding{
			Analyzer:    m.Name(),
			Title:       "No maintainers listed",
			Description: "Package has no listed maintainers",
			Severity:    SeverityHigh,
			                        ExploitExample: "A package with no listed maintainers cannot be traced to a responsible party.\n" +
			                                "    This is a common indicator of throwaway malicious packages:\n" +
			                                "      1. Attacker creates anonymous npm account\n" +
			                                "      2. Publishes package with credential-stealing postinstall\n" +
			                                "      3. Deletes account or lets it lapse — no accountability\n" +
			                                "    Legitimate packages always have identifiable maintainers.",
			                        Remediation: "Avoid using packages with no listed maintainers. If you must use it, perform a complete manual audit of the source code and all subsequent updates.",
			                })
			
	} else if len(maintainers) == 1 {
		findings = append(findings, Finding{
			Analyzer:    m.Name(),
			Title:       "Single maintainer",
			Description: fmt.Sprintf("Package has only one maintainer: %s", maintainers[0].Name),
			Severity:    SeverityLow,
			                        ExploitExample: "Single maintainer = single point of compromise:\n" +
			                                "    - Attacker phishes or credential-stuffs the maintainer's npm account\n" +
			                                "    - Publishes malicious update to all dependents\n" +
			                                "    - Real-world: the eslint-scope incident (2018) used a stolen maintainer token\n" +
			                                "      to publish a version that stole npm tokens from every install",
			                        Remediation: "Prefer packages with multiple maintainers for critical production dependencies to reduce the risk of a single point of failure or account compromise.",
			                })
			
	}

	// Check email domains
	for _, maint := range maintainers {
		for _, domain := range suspiciousEmailDomains {
			if strings.HasSuffix(strings.ToLower(maint.Email), "@"+domain) {
				findings = append(findings, Finding{
					Analyzer:    m.Name(),
					Title:       "Disposable email domain",
					Description: fmt.Sprintf("Maintainer %q uses disposable email domain %q", maint.Name, domain),
					Severity:    SeverityHigh,
					                                        ExploitExample: "Disposable emails enable untraceable malicious package publishing:\n" +
					                                                "    1. Register npm account with throwaway email (mailinator, guerrillamail)\n" +
					                                                "    2. Publish package mimicking a popular name or internal dependency\n" +
					                                                "    3. Email expires — no way to contact, recover, or identify the author\n" +
					                                                "    Legitimate open-source maintainers use persistent, verifiable identities.",
					                                        Remediation: "Packages published via disposable emails are high risk. Verify the maintainer's identity via other channels (e.g., GitHub, Twitter) before trusting the package.",
					                                })
					
			}
		}
	}

	// Check for recent publish (could indicate ownership transfer)
	m.checkPublishAnomalies(pkg, &findings)

	return findings, nil
}

func (m *MaintainerAnalyzer) checkPublishAnomalies(pkg *registry.PackageMetadata, findings *[]Finding) {
	if len(pkg.Time) == 0 {
		return
	}

	var publishTimes []time.Time
	for key, t := range pkg.Time {
		if key == "created" || key == "modified" {
			continue
		}
		publishTimes = append(publishTimes, t)
	}

	if len(publishTimes) < 2 {
		return
	}

	// Check if there was a long gap followed by sudden activity
	// (potential indicator of account takeover)
	created, hasCreated := pkg.Time["created"]
	modified, hasModified := pkg.Time["modified"]

	if hasCreated && hasModified {
		age := modified.Sub(created)
		if age > 365*24*time.Hour {
			// Package is old - check if there's been a very recent publish
			// after a long dormant period
			now := time.Now()
			if now.Sub(modified) < 30*24*time.Hour {
				// Check if there was a long gap before this recent publish
				var secondMostRecent time.Time
				for key, t := range pkg.Time {
					if key == "created" || key == "modified" {
						continue
					}
					if t.Before(modified) && t.After(secondMostRecent) {
						secondMostRecent = t
					}
				}
				if !secondMostRecent.IsZero() && modified.Sub(secondMostRecent) > 180*24*time.Hour {
					*findings = append(*findings, Finding{
						Analyzer:    m.Name(),
						Title:       "Sudden activity after long inactivity",
						Description: fmt.Sprintf("Package was completely inactive for %d days before this recent update.", int(modified.Sub(secondMostRecent).Hours()/24)),
						Severity:    SeverityMedium,
						ExploitExample: "This is a classic indicator of a package hijack (e.g., event-stream attack):\n" +
							"    1. A popular but unmaintained package sits idle for months or years.\n" +
							"    2. An attacker offers to 'help' maintain it or takes over a lapsed account.\n" +
							"    3. A new version is published containing malicious code.\n" +
							"    Users automatically receive the update, often before the hijack is detected.",
						Remediation: "Review the changes in this version carefully. Inactivity followed by a sudden update is a high-risk signal for account takeover or ownership transfer to an unknown party.",
					})
				}
			}
		}
	}
}
