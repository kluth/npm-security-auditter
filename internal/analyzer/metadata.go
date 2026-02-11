package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// MetadataAnalyzer checks for suspicious package metadata patterns.
type MetadataAnalyzer struct{}

func NewMetadataAnalyzer() *MetadataAnalyzer { return &MetadataAnalyzer{} }

func (m *MetadataAnalyzer) Name() string { return "metadata" }

func (m *MetadataAnalyzer) Analyze(_ context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	m.checkRepository(pkg, version, &findings)
	m.checkLicense(version, &findings)
	m.checkAge(pkg, &findings)
	m.checkDescription(pkg, version, &findings)
	m.checkRecentPublish(pkg, version, &findings)
	m.checkDeprecated(version, &findings)

	return findings, nil
}

func (m *MetadataAnalyzer) checkRecentPublish(pkg *registry.PackageMetadata, version *registry.PackageVersion, findings *[]Finding) {
	pubTime, ok := pkg.Time[version.Version]
	if !ok {
		return
	}

	since := time.Since(pubTime)
	if since < 24*time.Hour {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "Very recently published version",
			Description: fmt.Sprintf("Version %s was published only %s ago", version.Version, formatDuration(since)),
			Severity:    SeverityMedium,
			ExploitExample: "Supply chain attacks often involve publishing a malicious version and hoping victims auto-update before detection:\n" +
				"    - Many CI/CD systems use ^ ranges, pulling the latest minor/patch automatically\n" +
				"    - Malicious versions are usually caught within hours, but automated systems are fast\n" +
				"    - A 'just published' version has not yet been vetted by the community",
			Remediation: "Perform a manual review of the changes in this version if you need to use it immediately. Otherwise, wait 24-48 hours to ensure no security alerts are raised.",
		})
	}
}

func (m *MetadataAnalyzer) checkDeprecated(version *registry.PackageVersion, findings *[]Finding) {
	if version.Deprecated != "" {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "Deprecated package version",
			Description: fmt.Sprintf("This version is officially deprecated: %s", version.Deprecated),
			Severity:    SeverityMedium,
			ExploitExample: "Deprecated packages are no longer maintained and may contain unpatched vulnerabilities:\n" +
				"    - Use of deprecated code increases technical debt and security risk\n" +
				"    - Maintainers often deprecate a package to move users to a more secure or modern alternative",
			Remediation: "Follow the maintainer's advice and migrate to the recommended alternative package or version.",
		})
	}
}

func (m *MetadataAnalyzer) checkRepository(pkg *registry.PackageMetadata, version *registry.PackageVersion, findings *[]Finding) {
	repo := version.Repository
	if repo == nil {
		repo = pkg.Repository
	}

	if repo == nil {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "No repository URL",
			Description: "Package has no linked source repository",
			Severity:    SeverityMedium,
			ExploitExample: "Without a repository link, there is no way to diff published code against source:\n" +
				"    - Attacker publishes package with clean README but malicious code in dist/\n" +
				"    - No repo means no issue tracker, no commit history, no code review\n" +
				"    - `npm pack <pkg> && tar -xzf *.tgz` to manually inspect before installing",
			Remediation: "Manually inspect the package tarball using 'npm pack' before installing. Be cautious if the package has many downloads but no repository link.",
		})

		return
	}

	repoURL := strings.ToLower(repo.URL)
	if repoURL == "" {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "Empty repository URL",
			Description: "Package has a repository field but the URL is empty",
			Severity:    SeverityMedium,
			ExploitExample: "An empty repository URL provides false legitimacy:\n" +
				"    - The field exists (looks normal in metadata) but points nowhere\n" +
				"    - Automated tools may skip repo checks seeing the field is present\n" +
				"    - Always verify the URL actually resolves to a real source repository",
			Remediation: "Verify the source repository independently. This pattern is often used to deceive automated scanners.",
		})

		return
	}

	// Check for non-standard repository hosts
	knownHosts := []string{"github.com", "gitlab.com", "bitbucket.org"}
	isKnownHost := false
	for _, host := range knownHosts {
		if strings.Contains(repoURL, host) {
			isKnownHost = true
			break
		}
	}
	if !isKnownHost {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "Unusual repository host",
			Description: fmt.Sprintf("Repository URL %q is not on a well-known hosting platform", repo.URL),
			Severity:    SeverityLow,
			ExploitExample: "Attackers point repository URLs to domains they control:\n" +
				"    - Fake repo shows clean code while npm tarball contains the real payload\n" +
				"    - Unrecognized hosts could disappear, making forensics impossible\n" +
				"    - Verify the repo URL matches a known platform and the code matches the tarball",
			Remediation: "Check the reputation of the repository host. If it's a private server, perform additional verification of the package content.",
		})

	}
}

func (m *MetadataAnalyzer) checkLicense(version *registry.PackageVersion, findings *[]Finding) {
	if version.License == "" {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "No license specified",
			Description: "Package has no license field",
			Severity:    SeverityLow,
			ExploitExample: "Missing license is a red flag for throwaway malicious packages:\n" +
				"    - Legitimate packages almost always declare a license\n" +
				"    - Malicious packages skip metadata because they're meant to be short-lived\n" +
				"    - Also a legal risk: no license = all rights reserved by default",
			Remediation: "Contact the author to clarify the license. Using unlicensed code is a legal risk and may also indicate a lack of maintenance or professionalism.",
		})
		return
	}

	license := strings.ToUpper(version.License)
	// Check for copyleft licenses that might be problematic for some commercial projects
	copyleft := []string{"GPL", "AGPL", "LGPL", "MPL"}
	for _, l := range copyleft {
		if strings.Contains(license, l) {
			*findings = append(*findings, Finding{
				Analyzer:    m.Name(),
				Title:       "Copyleft license detected",
				Description: fmt.Sprintf("Package uses a %s license", version.License),
				Severity:    SeverityLow,
				ExploitExample: "Copyleft licenses (like GPL) may require you to release your source code:\n" +
					"    - This can be a significant legal and business risk for proprietary software\n" +
					"    - Compliance requires careful management of how the dependency is used",
				Remediation: "Consult with your legal team to ensure compliance with this license type.",
			})
			break
		}
	}

	// Check for "UNLICENSE" or "WTFPL" which are sometimes used in joke/malicious packages
	if strings.Contains(license, "WTFPL") || strings.Contains(license, "UNLICENSE") {
		*findings = append(*findings, Finding{
			Analyzer:       m.Name(),
			Title:          "Unconventional license",
			Description:    fmt.Sprintf("Package uses an unconventional license: %s", version.License),
			Severity:       SeverityLow,
			ExploitExample: "While sometimes legitimate, unconventional licenses are often seen in low-quality or 'troll' packages.",
			Remediation:    "Verify the authenticity of the package and ensure the license meets your project's legal standards.",
		})
	}
}

func (m *MetadataAnalyzer) checkAge(pkg *registry.PackageMetadata, findings *[]Finding) {
	created, ok := pkg.Time["created"]
	if !ok {
		return
	}

	age := time.Since(created)

	if age < 7*24*time.Hour {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "Very new package",
			Description: fmt.Sprintf("Package was created %s ago", formatDuration(age)),
			Severity:    SeverityMedium,
			ExploitExample: "Malicious packages are often published and weaponized within hours:\n" +
				"    1. Attacker creates package targeting a trending topic or typo\n" +
				"    2. Pushes to npm — clock starts ticking before detection\n" +
				"    3. Bots/SEO drive installs during the window before npm takedown\n" +
				"    Most malicious packages are removed within 24-48h, but the damage is done.",
			Remediation: "Wait at least 48 hours after a new package is published before installing it, or perform a manual code review if immediate use is required.",
		})

	} else if age < 30*24*time.Hour {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "New package",
			Description: fmt.Sprintf("Package was created %s ago", formatDuration(age)),
			Severity:    SeverityLow,
			ExploitExample: "New packages have no established trust or community review:\n" +
				"    - No download history to establish baseline behavior\n" +
				"    - Not yet indexed by most security scanners\n" +
				"    - Verify the author's other packages and reputation before installing",
			Remediation: "Monitor the package's community adoption and security reports before widespread use.",
		})

	}

	// Check number of versions vs age
	if age > 30*24*time.Hour && len(pkg.Versions) <= 1 {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "Stale package",
			Description: "Package is over 30 days old but has only one version",
			Severity:    SeverityLow,
			ExploitExample: "Stale single-version packages are prime targets for account takeover:\n" +
				"    - Maintainer may have abandoned the npm account\n" +
				"    - Weak or reused password makes credential stuffing viable\n" +
				"    - Attacker takes over and pushes v1.0.1 with malicious code\n" +
				"    - All existing dependents auto-update via semver ranges (^1.0.0)",
			Remediation: "Use stale packages with caution. Ensure you use a lockfile to prevent accidental updates to a potentially hijacked future release.",
		})

	}
}

func (m *MetadataAnalyzer) checkDescription(pkg *registry.PackageMetadata, version *registry.PackageVersion, findings *[]Finding) {
	desc := version.Description
	if desc == "" {
		desc = pkg.Description
	}

	if desc == "" {
		*findings = append(*findings, Finding{
			Analyzer:    m.Name(),
			Title:       "No description",
			Description: "Package has no description",
			Severity:    SeverityLow,
			ExploitExample: "Missing description is a signal of a hastily published package:\n" +
				"    - Legitimate packages describe their purpose for discoverability\n" +
				"    - Attack packages skip this because they rely on typos, not search",
			Remediation: "Verify the package's purpose manually. This is a low-severity signal but often found in low-quality or malicious packages.",
		})

	}
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days == 0 {
		hours := int(d.Hours())
		return fmt.Sprintf("%d hours", hours)
	}
	return fmt.Sprintf("%d days", days)
}
