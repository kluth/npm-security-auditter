package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// AntiDebugAnalyzer detects anti-debugging and anti-sandbox evasion
// techniques used by malware to avoid analysis.
// Based on USENIX Security 2021 "Detecting JavaScript Anti-Debugging Techniques in the Wild"
type AntiDebugAnalyzer struct{}

func NewAntiDebugAnalyzer() *AntiDebugAnalyzer {
	return &AntiDebugAnalyzer{}
}

func (a *AntiDebugAnalyzer) Name() string {
	return "anti-debug"
}

var (
	// Multiple debugger statements (trap pattern)
	debuggerStmtPattern = regexp.MustCompile(`\bdebugger\b`)

	// Timing-based detection: Date.now() difference checks
	timingCheckPattern = regexp.MustCompile(`(?i)Date\.now\(\)\s*-\s*\w+|performance\.now\(\)\s*-\s*\w+|\w+\s*-\s*Date\.now\(\)`)

	// Console override/disable
	consoleOverridePattern = regexp.MustCompile(`(?i)console\.\w+\s*=\s*function\s*\(\s*\)`)

	// Debug flag detection: v8debug, --inspect, --debug
	debugFlagPattern = regexp.MustCompile(`(?i)v8debug|--debug|--inspect|process\.execArgv|NODE_OPTIONS.*inspect`)
)

func (a *AntiDebugAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	// Debugger trap (multiple debugger statements)
	matches := debuggerStmtPattern.FindAllStringIndex(content, -1)
	if len(matches) >= 2 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       fmt.Sprintf("Debugger trap detected (%d statements)", len(matches)),
			Description: fmt.Sprintf("File %q contains %d debugger statements. Multiple debugger statements create a trap that makes debugging extremely difficult.", filename, len(matches)),
			Severity:    SeverityHigh,
			ExploitExample: "Debugger traps prevent analysis:\n" +
				"    setInterval(() => { debugger; }, 100);\n" +
				"    This pauses execution every 100ms when DevTools is open,\n" +
				"    making it impossible to analyze the running code.",
			Remediation: "Multiple debugger statements in npm packages are highly suspicious. Remove them to inspect the code.",
		})
	}

	// Timing-based debug detection
	if timingCheckPattern.MatchString(content) && strings.Contains(content, "exit") {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Timing-based debugger detection",
			Description: fmt.Sprintf("File %q measures execution timing to detect debuggers. Breakpoints cause measurable delays that malware exploits.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Timing detection avoids analysis:\n" +
				"    const t1 = Date.now();\n" +
				"    /* suspicious operation */\n" +
				"    if (Date.now() - t1 > 100) process.exit(0);\n" +
				"    Breakpoints make the check take longer, aborting malware in debuggers.",
			Remediation: "Investigate what the code does between the timing checks. This is an anti-analysis technique.",
		})
	}

	// Console override
	consoleMatches := consoleOverridePattern.FindAllString(content, -1)
	if len(consoleMatches) >= 2 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Console functions overridden",
			Description: fmt.Sprintf("File %q overrides %d console functions. This suppresses debugging output and hides malware activity.", filename, len(consoleMatches)),
			Severity:    SeverityHigh,
			ExploitExample: "Console override hides malware traces:\n" +
				"    console.log = () => {};\n" +
				"    console.warn = () => {};\n" +
				"    // Now any suspicious logging is silenced",
			Remediation: "Restore console functions to see what the code is trying to hide.",
		})
	}

	// Debug flag detection
	if debugFlagPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Node.js debug/inspect flag detection",
			Description: fmt.Sprintf("File %q checks for Node.js debugging flags (v8debug, --inspect, --debug). Malware uses this to detect analysis environments.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Debug flag detection:\n" +
				"    if (typeof v8debug === 'object') process.exit(0);\n" +
				"    if (process.execArgv.includes('--inspect')) return;\n" +
				"    Malware aborts when run under a debugger.",
			Remediation: "Code that checks for debugger flags has no legitimate purpose in npm packages.",
		})
	}

	return findings
}
