package analyzer

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ExfiltrationAnalyzer detects suspicious network destinations commonly used for data exfiltration.
type ExfiltrationAnalyzer struct{}

func NewExfiltrationAnalyzer() *ExfiltrationAnalyzer {
	return &ExfiltrationAnalyzer{}
}

func (a *ExfiltrationAnalyzer) Name() string {
	return "exfiltration-endpoints"
}

// exfiltrationEndpoint defines a suspicious destination pattern.
type exfiltrationEndpoint struct {
	Pattern     *regexp.Regexp
	Name        string
	Description string
	Severity    Severity
}

// Known exfiltration endpoints and patterns.
var exfiltrationEndpoints = []exfiltrationEndpoint{
	// Paste services (data drops)
	{
		Pattern:     regexp.MustCompile(`(?i)pastebin\.com|paste\.ee|hastebin\.com|dpaste\.org|paste\.mozilla\.org|ghostbin\.com|rentry\.co`),
		Name:        "Paste service",
		Description: "Connection to paste service commonly used for data exfiltration",
		Severity:    SeverityHigh,
	},
	// Discord webhooks (common C2 channel)
	{
		Pattern:     regexp.MustCompile(`(?i)discord(app)?\.com/api/webhooks/\d+/[\w-]+`),
		Name:        "Discord webhook",
		Description: "Discord webhook URL detected - commonly used for exfiltrating stolen credentials",
		Severity:    SeverityCritical,
	},
	// Telegram bot API
	{
		Pattern:     regexp.MustCompile(`(?i)api\.telegram\.org/bot[\w:]+`),
		Name:        "Telegram bot API",
		Description: "Telegram bot API URL detected - commonly used for C2 communication and data theft",
		Severity:    SeverityCritical,
	},
	// Slack webhooks
	{
		Pattern:     regexp.MustCompile(`(?i)hooks\.slack\.com/services/[\w/]+`),
		Name:        "Slack webhook",
		Description: "Slack webhook URL detected - can be used for data exfiltration",
		Severity:    SeverityHigh,
	},
	// GitHub API abuse (Shai-Hulud technique)
	{
		Pattern:     regexp.MustCompile(`(?i)api\.github\.com/(repos|gists|issues)`),
		Name:        "GitHub API",
		Description: "GitHub API call detected - can be abused to exfiltrate data via gists/issues (Shai-Hulud technique)",
		Severity:    SeverityMedium,
	},
	// Ngrok/tunneling services
	{
		Pattern:     regexp.MustCompile(`(?i)\.ngrok\.io|\.ngrok-free\.app|\.localtunnel\.me|\.serveo\.net|\.localhost\.run`),
		Name:        "Tunneling service",
		Description: "Connection to tunneling service that can expose local services or exfiltrate data",
		Severity:    SeverityHigh,
	},
	// Request bin / webhook testing services
	{
		Pattern:     regexp.MustCompile(`(?i)requestbin\.com|webhook\.site|pipedream\.net|hookbin\.com|beeceptor\.com`),
		Name:        "Request capture service",
		Description: "Request capture service URL detected - used to collect exfiltrated data",
		Severity:    SeverityHigh,
	},
	// File sharing services
	{
		Pattern:     regexp.MustCompile(`(?i)transfer\.sh|file\.io|0x0\.st|tmpfiles\.org|anonfiles\.com`),
		Name:        "Anonymous file sharing",
		Description: "Anonymous file sharing service detected - can be used to upload stolen data",
		Severity:    SeverityHigh,
	},
	// Raw GitHub content (often used to fetch second-stage payloads)
	{
		Pattern:     regexp.MustCompile(`(?i)raw\.githubusercontent\.com/[^/]+/[^/]+/(main|master)/.*\.(js|sh|ps1|exe|dll)`),
		Name:        "GitHub raw payload",
		Description: "Fetching executable content from GitHub raw - common second-stage loader pattern",
		Severity:    SeverityHigh,
	},
	// Cryptocurrency API (cryptojacking indicator)
	{
		Pattern:     regexp.MustCompile(`(?i)(coinhive|cryptoloot|minero|webminepool|crypto-loot|ppoi\.org|authedmine)\.`),
		Name:        "Crypto mining service",
		Description: "Cryptocurrency mining service detected - indicates cryptojacking",
		Severity:    SeverityCritical,
	},
	// Cloud metadata services (SSRF/credential theft)
	{
		Pattern:     regexp.MustCompile(`169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2`),
		Name:        "Cloud metadata endpoint",
		Description: "Cloud metadata service access - can leak IAM credentials and secrets",
		Severity:    SeverityCritical,
	},
	// Base URLs that are IP-based (suspicious)
	{
		Pattern:     regexp.MustCompile(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/`),
		Name:        "IP-based URL",
		Description: "Direct IP address URL detected - often used to evade domain-based detection",
		Severity:    SeverityMedium,
	},
	// Short URL services (hide true destination)
	{
		Pattern:     regexp.MustCompile(`(?i)(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|shorturl\.at)/\w+`),
		Name:        "URL shortener",
		Description: "URL shortener detected - can hide malicious destinations",
		Severity:    SeverityMedium,
	},
	// Russian/Chinese domains (high-risk for Western orgs)
	{
		Pattern:     regexp.MustCompile(`(?i)\.(ru|su|cn|tk|ml|ga|cf|gq|top|xyz|pw|cc|ws)/`),
		Name:        "High-risk TLD",
		Description: "High-risk top-level domain detected - commonly associated with malicious activity",
		Severity:    SeverityMedium,
	},
}

// scanContent analyzes content for exfiltration endpoints.
func (a *ExfiltrationAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, endpoint := range exfiltrationEndpoints {
		matches := endpoint.Pattern.FindAllString(content, 5) // Limit matches
		if len(matches) > 0 {
			// Deduplicate matches
			unique := make(map[string]bool)
			for _, m := range matches {
				// Truncate very long matches
				if len(m) > 100 {
					m = m[:100] + "..."
				}
				unique[m] = true
			}

			matchList := make([]string, 0, len(unique))
			for m := range unique {
				matchList = append(matchList, m)
			}

			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("%s detected", endpoint.Name),
				Description: fmt.Sprintf("%s in file %q: %s", endpoint.Description, filename, strings.Join(matchList, ", ")),
				Severity:    endpoint.Severity,
				ExploitExample: fmt.Sprintf(
					"Exfiltration pattern in %s:\n"+
						"    Found: %s\n"+
						"    Attack scenario:\n"+
						"      1. Package reads sensitive data (env vars, credentials, keys)\n"+
						"      2. Encodes and sends to attacker-controlled endpoint\n"+
						"      3. Attacker receives stolen data in real-time\n"+
						"    The Shai-Hulud worm used GitHub gists for exfiltration to blend with legitimate traffic.",
					filename, matchList[0]),
				Remediation: "Investigate why the package needs to communicate with this endpoint. If it's not essential functionality, remove the package immediately and rotate any exposed credentials.",
			})
		}
	}

	// Check for suspicious URL construction patterns
	findings = append(findings, a.detectURLConstruction(content, filename)...)

	return findings
}

// detectURLConstruction finds patterns that build URLs dynamically (evasion technique).
func (a *ExfiltrationAnalyzer) detectURLConstruction(content, filename string) []Finding {
	var findings []Finding

	// Patterns that construct URLs from parts to evade static analysis
	constructionPatterns := []struct {
		Pattern *regexp.Regexp
		Name    string
	}{
		{regexp.MustCompile(`(?i)['"]https?['"][\s]*\+[\s]*['"]://['"][\s]*\+`), "String concatenation URL"},
		{regexp.MustCompile(`(?i)\['h','t','t','p'\]\.join\(`), "Array join URL construction"},
		{regexp.MustCompile(`(?i)String\.fromCharCode\([^)]+\).*https?`), "CharCode URL construction"},
		{regexp.MustCompile(`(?i)atob\s*\(\s*['"][A-Za-z0-9+/=]+['"]\s*\)`), "Base64 decoded URL"},
		{regexp.MustCompile(`(?i)Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]+['"]`), "Buffer decoded string"},
		{regexp.MustCompile(`(?i)eval\s*\([^)]*https?`), "Eval with URL"},
	}

	for _, pat := range constructionPatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Dynamic URL construction detected",
				Description: fmt.Sprintf("File %q uses %s to build URLs dynamically, a common evasion technique", filename, pat.Name),
				Severity:    SeverityHigh,
				ExploitExample: "Attackers construct URLs from parts to evade static scanners:\n" +
					"    - \"ht\" + \"tp://\" + \"evil\" + \".com\" won't match 'http://evil.com'\n" +
					"    - Base64/hex encoding hides the true destination\n" +
					"    - This technique was used in the ua-parser-js compromise",
				Remediation: "Manually decode and inspect the constructed URLs. This pattern is almost never used in legitimate code.",
			})
		}
	}

	return findings
}

