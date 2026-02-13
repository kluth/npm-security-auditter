package analyzer

import (
	"fmt"
	"regexp"
)

// DeadMansSwitchAnalyzer detects conditional destruction payloads that
// trigger when C2 infrastructure is taken down. Based on Shai-Hulud 2.0
// (November 2025) which threatened to destroy git repositories and source
// directories when its exfiltration infrastructure was detected as removed.
type DeadMansSwitchAnalyzer struct{}

func NewDeadMansSwitchAnalyzer() *DeadMansSwitchAnalyzer {
	return &DeadMansSwitchAnalyzer{}
}

func (a *DeadMansSwitchAnalyzer) Name() string {
	return "dead-mans-switch"
}

var deadMansSwitchPatterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// Connectivity check + file deletion
	{
		regexp.MustCompile(`(?i)(?:fetch|http|https|request)\s*\([^)]+\)[\s\S]{0,300}(?:catch|error|fail|reject)[\s\S]{0,300}(?:rm\s+-rf|rmSync|rimraf|unlink|rmdir|deltree)`),
		"Dead man's switch: delete on connectivity failure",
		"Code deletes files when a network request fails, the exact pattern used by Shai-Hulud 2.0's destructive payload",
		SeverityCritical,
	},
	// Polling loop with destruction
	{
		regexp.MustCompile(`(?:setInterval|setTimeout)\s*\([\s\S]{0,300}(?:rm\s+-rf|rmSync|rimraf|unlink|rmdir|deltree)`),
		"Timed destruction loop",
		"Code runs a periodic destruction function, potentially a dead man's switch that activates on schedule",
		SeverityCritical,
	},
	// Conditional rm -rf based on network state
	{
		regexp.MustCompile(`(?:rm\s+-rf|rmSync|rimraf)\s*[\s(]+[^;]{0,50}(?:~|\/home|process\.env\.HOME|\$HOME|os\.homedir)`),
		"Home directory destruction",
		"Code attempts to delete the user's home directory, a destructive payload pattern",
		SeverityCritical,
	},
	// Git repository destruction
	{
		regexp.MustCompile(`(?:rm\s+-rf|rmSync|rimraf|unlink)\s*[\s(]+[^;]{0,50}\.git\b`),
		"Git repository destruction",
		"Code targets .git directories for deletion, destroying version history",
		SeverityCritical,
	},
	// Checking if external resources are still accessible
	{
		regexp.MustCompile(`(?i)(?:fetch|get|head|request)\s*\([^)]*\)[\s\S]{0,200}(?:status(?:Code)?|ok)\s*(?:!==?|!=)\s*(?:200|true)`),
		"Remote resource availability check",
		"Code checks whether external resources are accessible, potentially monitoring for takedown of C2 infrastructure",
		SeverityMedium,
	},
	// npm package existence check
	{
		regexp.MustCompile(`(?:registry\.npmjs\.org|npm\s+view|npm\s+info)[\s\S]{0,200}(?:error|404|not\s*found)[\s\S]{0,200}(?:rm|delete|unlink|destroy)`),
		"Package existence check with destruction",
		"Code checks npm registry for a package and triggers destruction if not found, a dead man's switch monitoring for package takedown",
		SeverityCritical,
	},
	// GitHub repository existence check
	{
		regexp.MustCompile(`(?:api\.github\.com|github\.com)[\s\S]{0,200}(?:404|not\s*found)[\s\S]{0,200}(?:rm|delete|unlink|destroy)`),
		"GitHub repo check with destruction",
		"Code checks GitHub for a repository and triggers destruction if removed, monitoring for security team takedowns",
		SeverityCritical,
	},
	// Source code directory destruction
	{
		regexp.MustCompile(`(?:rm\s+-rf|rmSync|rimraf(?:\.sync)?)\s*[\s(]+[^;]{0,80}(?:['"](?:src|source|lib|dist|build|node_modules)['"]|/(?:src|source|lib|dist|build|node_modules)\b)`),
		"Source directory destruction",
		"Code targets source code directories for deletion, a destructive escalation pattern",
		SeverityHigh,
	},
}

func (a *DeadMansSwitchAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range deadMansSwitchPatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "Dead man's switch (Shai-Hulud 2.0, November 2025):\n" +
					"    1. Malware periodically checks if its C2/exfil repos still exist\n" +
					"    2. If security teams take down the repos (expected response)\n" +
					"    3. Dead man's switch triggers: rm -rf ~/ destroys all user data\n" +
					"    4. Creates a hostage situation: leave worm active OR lose data\n" +
					"    Impact: threatened to destroy data across 796 compromised packages",
				Remediation: "CRITICAL: Do not remove the package's C2 infrastructure without first neutralizing the dead man's switch. Disconnect the affected system from the network, then remove the malware.",
			})
		}
	}

	return findings
}
