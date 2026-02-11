package analyzer

import (
	"fmt"
	"regexp"
)

// TaintAnalyzer performs taint-based code slicing to track data flow from
// sensitive sources (process.env, fs.read, etc.) to dangerous sinks
// (fetch, exec, eval, etc.). This detects exfiltration chains that
// individual pattern matchers miss.
type TaintAnalyzer struct{}

func NewTaintAnalyzer() *TaintAnalyzer {
	return &TaintAnalyzer{}
}

func (a *TaintAnalyzer) Name() string {
	return "taint-analysis"
}

// Source categories - where sensitive data comes from.
var taintSources = []struct {
	pattern  *regexp.Regexp
	category string
}{
	{regexp.MustCompile(`(?i)process\.env`), "environment variables"},
	{regexp.MustCompile(`(?i)fs\.readFile|readFileSync|fs\.read\b`), "file system read"},
	{regexp.MustCompile(`(?i)\.npmrc|\.ssh|\.aws|\.env\b|\.bash_history`), "sensitive file access"},
	{regexp.MustCompile(`(?i)os\.homedir|os\.hostname|os\.userInfo`), "OS information"},
	{regexp.MustCompile(`(?i)Buffer\.from\(\s*process\.env`), "encoded environment data"},
	{regexp.MustCompile(`(?i)crypto\.createHash|\.digest\(`), "cryptographic operation on data"},
	{regexp.MustCompile(`(?i)fetch\s*\(|axios\.\w+\(|http\.get\(|https\.get\(`), "network response data"},
}

// Sink categories - where data goes that's dangerous.
var taintSinks = []struct {
	pattern  *regexp.Regexp
	category string
	severity Severity
}{
	{regexp.MustCompile(`(?i)fetch\s*\(|axios\.|(?:http|https)\.request|(?:require\s*\(\s*['"]https?['"]\s*\)\s*\.request)|\.post\(|\.get\(`), "network request", SeverityCritical},
	{regexp.MustCompile(`(?i)\beval\s*\(|Function\s*\(`), "code execution", SeverityCritical},
	{regexp.MustCompile(`(?i)child_process|\.exec\(|\.execSync\(|\.spawn\(`), "process execution", SeverityCritical},
	{regexp.MustCompile(`(?i)dns\.lookup|dns\.resolve|net\.connect|net\.Socket`), "DNS/network exfiltration", SeverityCritical},
	{regexp.MustCompile(`(?i)WebSocket|\.send\(`), "WebSocket transmission", SeverityHigh},
	{regexp.MustCompile(`(?i)fs\.writeFile|writeFileSync|fs\.append`), "file system write", SeverityHigh},
}

func (a *TaintAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	// Detect which sources and sinks are present
	var activeSources []string
	var activeSinks []struct {
		category string
		severity Severity
	}

	for _, src := range taintSources {
		if src.pattern.MatchString(content) {
			activeSources = append(activeSources, src.category)
		}
	}

	for _, sink := range taintSinks {
		if sink.pattern.MatchString(content) {
			activeSinks = append(activeSinks, struct {
				category string
				severity Severity
			}{sink.category, sink.severity})
		}
	}

	// If both sources and sinks exist in the same file, flag taint flow
	if len(activeSources) > 0 && len(activeSinks) > 0 {
		for _, source := range activeSources {
			for _, sink := range activeSinks {
				// Determine the most dangerous combinations
				severity := sink.severity
				title := fmt.Sprintf("Taint data flow: %s -> %s", source, sink.category)

				// Boost severity for known dangerous pairs
				if isCriticalTaintPair(source, sink.category) {
					severity = SeverityCritical
				}

				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       title,
					Description: fmt.Sprintf("File %q reads from %s and sends data to %s. This pattern indicates potential data exfiltration or code injection.", filename, source, sink.category),
					Severity:    severity,
					ExploitExample: fmt.Sprintf("Data flows from %s to %s:\n", source, sink.category) +
						"    1. Sensitive data is read (credentials, tokens, keys)\n" +
						"    2. Data may be encoded/transformed (base64, JSON.stringify)\n" +
						"    3. Data is sent to an external endpoint or executed\n" +
						"    This is the fundamental pattern of all credential theft malware.",
					Remediation: "Trace the data flow manually. Verify the data source is not sensitive and the destination is legitimate.",
				})
			}
		}
	}

	return findings
}

// isCriticalTaintPair checks if a source-sink combination is particularly dangerous.
func isCriticalTaintPair(source, sink string) bool {
	criticalPairs := map[string][]string{
		"environment variables":    {"network request", "DNS/network exfiltration", "WebSocket transmission"},
		"sensitive file access":    {"network request", "DNS/network exfiltration", "WebSocket transmission"},
		"file system read":         {"network request", "DNS/network exfiltration"},
		"encoded environment data": {"network request", "DNS/network exfiltration"},
		"OS information":           {"network request"},
	}

	sinks, ok := criticalPairs[source]
	if !ok {
		return false
	}
	for _, s := range sinks {
		if s == sink {
			return true
		}
	}
	return false
}
