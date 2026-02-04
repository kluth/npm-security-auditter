package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/matthias/auditter/internal/registry"
)

// DepsAnalyzer analyzes the dependency tree for risks.
type DepsAnalyzer struct{}

func NewDepsAnalyzer() *DepsAnalyzer { return &DepsAnalyzer{} }

func (d *DepsAnalyzer) Name() string { return "dependencies" }

func (d *DepsAnalyzer) Analyze(_ context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	deps := version.Dependencies
	devDeps := version.DevDependencies

	totalDeps := len(deps)

	        // Flag excessive dependencies
	        if totalDeps > 50 {
	                findings = append(findings, Finding{
	                        Analyzer:    d.Name(),
	                        Title:       "Excessive dependencies",
	                        Description: fmt.Sprintf("Package has %d direct dependencies", totalDeps),
	                        Severity:    SeverityMedium,
	                        ExploitExample: fmt.Sprintf(
	                                "Each dependency is an entry point for supply chain attacks:\n"+
	                                        "    - %d direct deps means potentially hundreds of transitive deps\n"+
	                                        "    - Compromising ANY one of them compromises this package\n"+
	                                        "    - event-stream attack: malicious code was 3 levels deep in the dep tree\n"+
	                                        "    - Run `npm ls --all` to see the full transitive dependency tree", totalDeps),
	                        Remediation: "Review the dependency list and remove any unnecessary packages. For critical projects, consider vendoring small dependencies or implementing stricter sub-dependency auditing.",
	                })
	        } else if totalDeps > 20 {
	                findings = append(findings, Finding{
	                        Analyzer:    d.Name(),
	                        Title:       "Many dependencies",
	                        Description: fmt.Sprintf("Package has %d direct dependencies", totalDeps),
	                        Severity:    SeverityLow,
	                        ExploitExample: "A wide dependency tree increases the attack surface:\n" +
	                                "    - More packages = more maintainer accounts to potentially compromise\n" +
	                                "    - Each transitive dependency is an implicit trust relationship\n" +
	                                "    - Consider auditing the full tree: npm audit && npm ls --all",
	                        Remediation: "Regularly audit your dependencies and keep them updated to minimize the risk from stale or vulnerable sub-dependencies.",
	                })
	        }
		// Check for dependency confusion risks
	d.checkConfusionRisks(deps, &findings)
	d.checkConfusionRisks(devDeps, &findings)

	// Check for wildcard/latest versions
	d.checkUnsafeVersions(deps, &findings)

	// Check for circular dependencies (direct)
	d.checkCircularDependencies(pkg.Name, deps, &findings)

	return findings, nil
}

func (d *DepsAnalyzer) checkCircularDependencies(pkgName string, deps map[string]string, findings *[]Finding) {
	for name := range deps {
		if name == pkgName {
			*findings = append(*findings, Finding{
				Analyzer:    d.Name(),
				Title:       "Self-referencing dependency",
				Description: fmt.Sprintf("Package %q lists itself as a dependency", pkgName),
				Severity:    SeverityMedium,
				ExploitExample: "Self-referencing dependencies can cause infinite loops in some build or installation tools.",
				Remediation: "Remove the self-reference from the dependencies list in package.json.",
			})
		}
	}
}

// checkConfusionRisks looks for patterns that might indicate dependency confusion.
func (d *DepsAnalyzer) checkConfusionRisks(deps map[string]string, findings *[]Finding) {
	for name := range deps {
		// Unscoped packages with internal-looking names
		if !strings.HasPrefix(name, "@") && isInternalLookingName(name) {
			*findings = append(*findings, Finding{
				Analyzer:    d.Name(),
				Title:       "Potential dependency confusion",
				Description: fmt.Sprintf("Dependency %q has an internal-looking name but is unscoped", name),
				Severity:    SeverityHigh,
				ExploitExample: fmt.Sprintf(
					"Dependency confusion attack (see: Alex Birsan's research):\n"+
						"    1. Company uses private package %q internally\n"+
						"    2. Attacker publishes %q on public npm with higher version\n"+
						"    3. Build system resolves from public npm instead of private registry\n"+
						"    4. Attacker's code runs inside the company's CI/CD pipeline\n"+
						"    This attack compromised Apple, Microsoft, and PayPal in 2021.",
					                                        name, name),
					                                Remediation: fmt.Sprintf("Use scoped packages (e.g., @company/%s) for all internal dependencies to prevent them from being resolved from the public registry. Configure your .npmrc to point to your private registry for the scope.", name),
					                        })
					
		}
	}
}

// isInternalLookingName returns true if a package name looks like it could be an internal package.
func isInternalLookingName(name string) bool {
	internalPrefixes := []string{"internal-", "private-", "corp-", "company-"}
	internalSuffixes := []string{"-internal", "-private", "-corp"}

	lower := strings.ToLower(name)
	for _, prefix := range internalPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// checkUnsafeVersions flags dependencies using wildcard or latest versions.
func (d *DepsAnalyzer) checkUnsafeVersions(deps map[string]string, findings *[]Finding) {
	for name, version := range deps {
		if version == "*" || version == "latest" || version == "" {
			*findings = append(*findings, Finding{
				Analyzer:    d.Name(),
				Title:       "Unsafe dependency version",
				Description: fmt.Sprintf("Dependency %q uses version %q which could resolve to any version", name, version),
				Severity:    SeverityHigh,
				ExploitExample: fmt.Sprintf(
					"Wildcard/latest versions allow instant supply chain compromise:\n"+
						"    - %q is pinned to %q — resolves to whatever is newest\n"+
						"    - If an attacker compromises %q, every install gets the malicious version\n"+
						"    - No lockfile protection: npm install in CI always fetches latest\n"+
						"    - Fix: pin exact versions or use a lockfile (package-lock.json)",
					                                        name, version, name),
					                                Remediation: "Pin dependencies to exact versions or use a lockfile (package-lock.json). Never use '*' or 'latest' for production dependencies.",
					                        })
					
		} else if strings.HasPrefix(version, ">") && !strings.Contains(version, "<") {
			*findings = append(*findings, Finding{
				Analyzer:    d.Name(),
				Title:       "Open-ended version range",
				Description: fmt.Sprintf("Dependency %q uses open-ended version range %q", name, version),
				Severity:    SeverityMedium,
				ExploitExample: fmt.Sprintf(
					"Open-ended ranges accept any future version:\n"+
						"    - %q at %q has no upper bound\n"+
						"    - A compromised future release auto-installs for all consumers\n"+
						"    - Use exact versions or caret ranges with lockfiles instead",
					                                        name, version),
					                                Remediation: "Add an upper bound to your version range (e.g., ^1.2.3 instead of >1.2.3) to prevent accidental upgrades to incompatible or compromised major versions.",
					                        })
					
		}
	}
}
