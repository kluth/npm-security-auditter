package policy

import (
	"fmt"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/reporter"
)

// Policy defines security rules for the audit.
type Policy struct {
	MaxSeverity    analyzer.Severity `yaml:"max-severity"`
	BannedLicenses []string          `yaml:"banned-licenses"`
	AllowScripts   bool              `yaml:"allow-scripts"`
	RequiredScopes []string          `yaml:"required-scopes"` // e.g. ["@myorg"] - all packages must be in these scopes
	BannedPackages []string          `yaml:"banned-packages"` // explicit blocklist
}

// Violation represents a policy violation.
type Violation struct {
	Rule        string
	Description string
	Package     string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s (%s)", v.Rule, v.Description, v.Package)
}

// Evaluate checks a project report against the policy.
func Evaluate(report *reporter.ProjectReport, p *Policy) []Violation {
	var violations []Violation

	for _, r := range report.Reports {
		// 1. Max Severity Check
		if p.MaxSeverity > 0 { // 0 is uninitialized, usually SeverityLow is 0 but let's assume explicit setting
			// Severity is an int enum where higher is worse
			// If we say "max-severity: medium", we block HIGH and CRITICAL.
			// Actually "max-severity" usually means "fail if severity >= X".
			// Let's interpret it as "fail on findings >= this severity" (same as --fail-on).
			for _, res := range r.Results {
				for _, f := range res.Findings {
					if f.Severity >= p.MaxSeverity {
						violations = append(violations, Violation{
							Rule:        "max-severity",
							Description: fmt.Sprintf("Finding %q has severity %s (limit: %s)", f.Title, f.Severity, p.MaxSeverity),
							Package:     r.Package,
						})
					}
				}
			}
		}

		// 2. Banned Licenses
		if len(p.BannedLicenses) > 0 && r.Info.License != "" {
			for _, banned := range p.BannedLicenses {
				if strings.EqualFold(r.Info.License, banned) {
					violations = append(violations, Violation{
						Rule:        "banned-license",
						Description: fmt.Sprintf("License %q is banned", r.Info.License),
						Package:     r.Package,
					})
				}
			}
		}

		// 3. Allow Scripts
		if !p.AllowScripts && r.Info.HasScripts {
			violations = append(violations, Violation{
				Rule:        "no-scripts",
				Description: "Package contains install scripts but scripts are disabled by policy",
				Package:     r.Package,
			})
		}

		// 4. Banned Packages
		for _, banned := range p.BannedPackages {
			if r.Package == banned {
				violations = append(violations, Violation{
					Rule:        "banned-package",
					Description: fmt.Sprintf("Package %q is explicitly banned", r.Package),
					Package:     r.Package,
				})
			}
		}

		// 5. Required Scopes
		if len(p.RequiredScopes) > 0 {
			hasScope := false
			for _, scope := range p.RequiredScopes {
				if strings.HasPrefix(r.Package, scope+"/") {
					hasScope = true
					break
				}
			}
			if !hasScope {
				violations = append(violations, Violation{
					Rule:        "required-scope",
					Description: fmt.Sprintf("Package %q does not belong to required scopes: %v", r.Package, p.RequiredScopes),
					Package:     r.Package,
				})
			}
		}
	}

	return violations
}
