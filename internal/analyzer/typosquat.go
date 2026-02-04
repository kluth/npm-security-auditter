package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/matthias/auditter/internal/registry"
)

// popularPackages is a list of popular npm packages to check for typosquatting.
var popularPackages = []string{
	"express", "react", "angular", "vue", "lodash", "axios",
	"moment", "webpack", "babel", "typescript", "eslint", "prettier",
	"jest", "mocha", "chai", "next", "nuxt", "svelte",
	"underscore", "jquery", "bootstrap", "tailwindcss",
	"commander", "chalk", "inquirer", "yargs", "minimist",
	"request", "node-fetch", "got", "superagent",
	"mongoose", "sequelize", "knex", "prisma",
	"socket.io", "ws", "rxjs", "ramda",
	"debug", "dotenv", "uuid", "nanoid",
	"@angular/core", "@angular/cli", "@types/node",
	"@babel/core", "@babel/preset-env",
	"@nestjs/core", "@nestjs/common",
	"@testing-library/react", "@testing-library/jest-dom",
}

// TyposquatAnalyzer detects potential typosquatting.
type TyposquatAnalyzer struct{}

func NewTyposquatAnalyzer() *TyposquatAnalyzer { return &TyposquatAnalyzer{} }

func (t *TyposquatAnalyzer) Name() string { return "typosquatting" }

func (t *TyposquatAnalyzer) Analyze(_ context.Context, pkg *registry.PackageMetadata, _ *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding
	name := pkg.Name

	for _, popular := range popularPackages {
		if name == popular {
			return nil, nil // It IS the popular package
		}

		dist := levenshteinDistance(normalizeName(name), normalizeName(popular))
		if dist > 0 && dist <= 2 {
			sev := SeverityMedium
			if dist == 1 {
				sev = SeverityHigh
			}
			                        			findings = append(findings, Finding{
			                        				Analyzer:    t.Name(),
			                        				Title:       fmt.Sprintf("Suspiciously similar to popular package %q", popular),
			                        				Description: fmt.Sprintf("Package name %q is very similar to the well-known package %q (difference: %d characters).", name, popular, dist),
			                        				Severity:    sev,
			                        				ExploitExample: fmt.Sprintf(
			                        					"Typosquatting attack scenario:\n"+
			                        						"    1. Attacker registers %q (similar to popular %q)\n"+
			                        						"    2. Adds a postinstall script with credential-stealing payload\n"+
			                        						"    3. Waits for developers to mistype: npm install %s\n"+
			                        						"    4. Every typo = full code execution on the developer's machine\n"+
			                        						"    Real-world: crossenv (typosquat of cross-env) stole npm tokens\n"+
			                        						"    from thousands of developers before being caught.",
			                        					name, popular, name),
			                        				Remediation: fmt.Sprintf("Verify that you intended to install %q and not %q. If you intended the latter, uninstall this package immediately and check your system for unauthorized changes.", name, popular),
			                        			})
			                        		}
			                        	}			
			        // Check for common typosquatting patterns
			        if pattern := detectTyposquatPattern(name); pattern != "" {
			                findings = append(findings, Finding{
			                        Analyzer:    t.Name(),
			                        Title:       "Typosquatting pattern detected",
			                        Description: pattern,
			                        Severity:    SeverityHigh,
			                        ExploitExample: "Name-variant typosquatting is a common supply chain attack vector:\n" +
			                                "    - Attacker publishes a package with an extra hyphen, suffix, or prefix\n" +
			                                "    - Auto-complete, copy-paste errors, or SEO tricks lead victims to install it\n" +
			                                "    - Package contains identical functionality PLUS a hidden malicious payload\n" +
			                                "    - The lodash-utils incident and event-stream attack both used this pattern",
			                        Remediation: "Carefully verify the package name. This variant pattern is highly suspicious and often used to deceive users into installing malicious clones of popular libraries.",
			                })
			        }
				return findings, nil
}

func normalizeName(name string) string {
	// Strip scope prefix for comparison
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	return strings.ToLower(name)
}

func detectTyposquatPattern(name string) string {
	normalized := normalizeName(name)

	// Check for hyphen/no-hyphen variants
	withoutHyphen := strings.ReplaceAll(normalized, "-", "")
	for _, popular := range popularPackages {
		popNorm := normalizeName(popular)
		popNoHyphen := strings.ReplaceAll(popNorm, "-", "")

		// Package adds/removes hyphens from popular package
		if normalized != popNorm && withoutHyphen == popNoHyphen {
			return fmt.Sprintf("Hyphen variant of %q", popular)
		}

		// Package adds a common prefix/suffix
		for _, affix := range []string{"js", "-js", "node-", "-node", "get-", "-get", ".js"} {
			if normalized == popNorm+affix || normalized == affix+popNorm {
				return fmt.Sprintf("Affix variant (%s) of %q", affix, popular)
			}
		}
	}

	return ""
}

// levenshteinDistance computes the Levenshtein edit distance between two strings.
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}

	return matrix[len(a)][len(b)]
}

func min(values ...int) int {
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}
