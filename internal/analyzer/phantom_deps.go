package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// PhantomDepsAnalyzer detects require() calls for modules not declared in
// package.json dependencies, and flags dangerous Node.js builtin usage.
// Based on research from Socket.dev and Phylum on phantom dependency attacks.
type PhantomDepsAnalyzer struct{}

func NewPhantomDepsAnalyzer() *PhantomDepsAnalyzer {
	return &PhantomDepsAnalyzer{}
}

func (a *PhantomDepsAnalyzer) Name() string {
	return "phantom-deps"
}

var (
	// Match require('module-name') or require("module-name")
	requireCallPattern = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// Safe Node.js builtins that are commonly used and not suspicious
	safeBuiltins = map[string]bool{
		"path": true, "fs": true, "os": true, "util": true,
		"url": true, "querystring": true, "stream": true,
		"events": true, "assert": true, "buffer": true,
		"crypto": true, "zlib": true, "string_decoder": true,
		"timers": true, "console": true, "constants": true,
	}

	// Dangerous builtins that enable code execution, network access, etc.
	dangerousBuiltins = map[string]bool{
		"child_process": true, "net": true, "dgram": true,
		"http": true, "https": true, "http2": true,
		"tls": true, "dns": true, "cluster": true,
		"vm": true, "worker_threads": true, "v8": true,
	}
)

func (a *PhantomDepsAnalyzer) scanContentWithDeps(content string, filename string, declaredDeps map[string]string) []Finding {
	var findings []Finding

	matches := requireCallPattern.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return findings
	}

	var phantomDeps []string
	var dangerousUsed []string

	for _, m := range matches {
		modName := m[1]

		// Skip relative imports
		if strings.HasPrefix(modName, ".") || strings.HasPrefix(modName, "/") {
			continue
		}

		// Get the package name (handle scoped packages like @org/pkg)
		pkgName := modName
		if strings.Contains(modName, "/") && !strings.HasPrefix(modName, "@") {
			pkgName = strings.SplitN(modName, "/", 2)[0]
		}

		// Check if it's a builtin
		if safeBuiltins[modName] {
			continue
		}
		if dangerousBuiltins[modName] {
			dangerousUsed = append(dangerousUsed, modName)
			continue
		}

		// Check if it's declared in dependencies
		if _, ok := declaredDeps[pkgName]; !ok {
			phantomDeps = append(phantomDeps, modName)
		}
	}

	// Flag phantom (undeclared) dependencies
	if len(phantomDeps) > 0 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       fmt.Sprintf("Phantom undeclared dependencies detected (%d modules)", len(phantomDeps)),
			Description: fmt.Sprintf("File %q requires modules not declared in package.json: %s. These could be dependency confusion or phantom dependency attacks.", filename, strings.Join(phantomDeps, ", ")),
			Severity:    SeverityHigh,
			ExploitExample: "Phantom dependency attack:\n" +
				"    // package.json has no 'evil-pkg' dependency\n" +
				"    const x = require('evil-pkg');\n" +
				"    // Attacker publishes 'evil-pkg' to npm registry\n" +
				"    // Node resolves it from global or hoisted node_modules",
			Remediation: "Verify all required modules are explicitly declared in package.json dependencies.",
		})
	}

	// Flag dangerous builtins (especially multiple ones together)
	if len(dangerousUsed) >= 2 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       fmt.Sprintf("Dangerous builtin combination (%d modules)", len(dangerousUsed)),
			Description: fmt.Sprintf("File %q uses multiple dangerous Node.js builtins: %s. This combination enables code execution and network exfiltration.", filename, strings.Join(dangerousUsed, ", ")),
			Severity:    SeverityHigh,
			ExploitExample: "Dangerous builtin combination:\n" +
				"    const cp = require('child_process');\n" +
				"    const net = require('net');\n" +
				"    // Execute commands and send output over network",
			Remediation: "Review why the package needs access to process execution and network primitives simultaneously.",
		})
	}

	return findings
}
