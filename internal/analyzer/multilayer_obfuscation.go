package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// MultilayerObfuscationAnalyzer detects multi-layer obfuscation patterns
// including nested eval chains, XOR ciphers, self-decoding wrappers,
// and heavy hex/unicode escape sequences used to hide malicious payloads.
// Based on Cycode, Aikido, and 12-stage npm malware research.
type MultilayerObfuscationAnalyzer struct{}

func NewMultilayerObfuscationAnalyzer() *MultilayerObfuscationAnalyzer {
	return &MultilayerObfuscationAnalyzer{}
}

func (a *MultilayerObfuscationAnalyzer) Name() string {
	return "multilayer-obfuscation"
}

var (
	// Nested eval: eval(eval(...)) or eval(atob(eval(...)))
	nestedEvalPattern = regexp.MustCompile(`eval\s*\(\s*(?:eval|atob|decodeURIComponent|unescape|Buffer\.from)\s*\(`)

	// XOR cipher patterns: charCode ^ key or c ^ key
	xorCipherPattern = regexp.MustCompile(`(?:charCodeAt|fromCharCode)\s*\([^)]*\)\s*\^\s*\d+|\w+\s*\^\s*(?:key|0x[0-9a-fA-F]+|\d{2,})`)

	// Self-executing function wrapper: (function(){...})()
	iifePattern = regexp.MustCompile(`\(\s*function\s*\(\s*\)\s*\{`)

	// Heavy hex escape: 5+ hex escapes in a single assignment
	heavyHexPattern = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){5,}`)

	// Non-ASCII identifiers used as variable names (Katakana, CJK, etc.)
	nonASCIIIdentPattern = regexp.MustCompile("(?:const|let|var|function)\\s+[^\x00-\x7F]+\\s*=")
)

func (a *MultilayerObfuscationAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	// Nested eval chain detection
	if nestedEvalPattern.MatchString(content) {
		// Count nesting depth
		evalCount := strings.Count(content, "eval(")
		severity := SeverityHigh
		if evalCount >= 2 {
			severity = SeverityCritical
		}
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       fmt.Sprintf("Nested eval/decode chain (depth: %d)", evalCount),
			Description: fmt.Sprintf("File %q contains nested eval/decode calls. This multi-layer unwrapping pattern is characteristic of staged malware payloads.", filename),
			Severity:    severity,
			ExploitExample: "Nested eval chains hide payloads through multiple layers:\n" +
				"    eval(eval(atob('base64_of(eval(atob(...)))')))\n" +
				"    Each layer must be decoded to reveal the next.\n" +
				"    The 12-stage npm dropper used this exact technique.\n" +
				"    Real: eval(atob('ZXZhbChhdG9i...')) → eval(atob(...)) → require('child_process')",
			Remediation: "Manually decode each layer to reveal the final payload. This pattern is almost never legitimate.",
		})
	}

	// XOR cipher obfuscation
	if xorCipherPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "XOR cipher obfuscation detected",
			Description: fmt.Sprintf("File %q uses XOR operations to decode strings. XOR ciphers are a common malware obfuscation technique.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "XOR cipher hides strings from static analysis:\n" +
				"    const encoded = [0x4b, 0x47, 0x5e, 0x5e, 0x45];\n" +
				"    const decoded = encoded.map(c => String.fromCharCode(c ^ 42)).join('');\n" +
				"    // Decodes to a dangerous string invisible to scanners",
			Remediation: "Determine the XOR key and decode the obfuscated strings to inspect the actual values.",
		})
	}

	// Self-decoding wrapper: IIFE + eval + decode function
	hasIIFE := iifePattern.MatchString(content)
	hasEval := strings.Contains(content, "eval(")
	hasDecode := strings.Contains(content, "atob(") || strings.Contains(content, "decodeURIComponent(") || strings.Contains(content, "unescape(")
	if hasIIFE && hasEval && hasDecode {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Self-decoding wrapper function",
			Description: fmt.Sprintf("File %q contains an IIFE that decodes and evaluates its own payload. This self-extracting pattern is typical of packed malware.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Self-decoding wrappers are multi-layer payloads:\n" +
				"    (function(){var a=function(b){return atob(b)};\n" +
				"     eval(a('bWFsaWNpb3VzIGNvZGU='))})();\n" +
				"    The IIFE executes immediately, decoding and running the payload.",
			Remediation: "Extract and decode the payload inside the wrapper. Self-extracting code is almost never legitimate in npm packages.",
		})
	}

	// Heavy hex escape usage
	matches := heavyHexPattern.FindAllString(content, -1)
	if len(matches) >= 3 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       fmt.Sprintf("Heavy hex escape obfuscation (%d occurrences)", len(matches)),
			Description: fmt.Sprintf("File %q uses extensive hex escape sequences to encode strings. This hides the actual string content from human review.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Hex escapes hide identifiers from scanners:\n" +
				"    const a = '\\x72\\x65\\x71\\x75\\x69\\x72\\x65'; // 'require'\n" +
				"    const b = '\\x63\\x68\\x69\\x6c\\x64_\\x70\\x72\\x6f\\x63\\x65\\x73\\x73'; // 'child_process'\n" +
				"    Scanners looking for literal 'require' or 'child_process' will miss this.",
			Remediation: "Decode all hex escape sequences to determine the actual strings being constructed.",
		})
	}

	// Non-ASCII identifier obfuscation
	if nonASCIIIdentPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Non-ASCII identifier obfuscation",
			Description: fmt.Sprintf("File %q uses non-ASCII characters (CJK, Katakana, etc.) as variable names. This technique was used in the 12-stage npm malware dropper.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Non-ASCII identifiers confuse analysis tools:\n" +
				"    const アイウ = '\\x65\\x76\\x61\\x6c'; // 'eval' in Katakana var\n" +
				"    globalThis[アイウ](payload);\n" +
				"    Many tools cannot display or search for these names.",
			Remediation: "Rename variables to ASCII to understand the code. Non-ASCII identifiers in npm packages are suspicious.",
		})
	}

	return findings
}
