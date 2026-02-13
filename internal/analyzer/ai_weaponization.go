package analyzer

import (
	"fmt"
	"regexp"
)

// AIWeaponizationAnalyzer detects attempts to weaponize installed AI CLI tools
// (Claude, Gemini, Amazon Q, GitHub Copilot) as attack capabilities.
// Based on the s1ngularity attack (August 2025) which used victim-installed
// AI tools to perform reconnaissance and credential harvesting.
type AIWeaponizationAnalyzer struct{}

func NewAIWeaponizationAnalyzer() *AIWeaponizationAnalyzer {
	return &AIWeaponizationAnalyzer{}
}

func (a *AIWeaponizationAnalyzer) Name() string {
	return "ai-weaponization"
}

var aiWeaponPatterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// AI CLI tool invocations via child_process
	{
		regexp.MustCompile(`(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"]claude\b`),
		"Claude CLI weaponization",
		"Code invokes the Claude CLI tool via child_process, potentially using it to search for credentials or perform reconnaissance",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"]gemini\b`),
		"Gemini CLI weaponization",
		"Code invokes the Gemini CLI tool via child_process for potential credential harvesting",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"]\bq\b`),
		"Amazon Q CLI weaponization",
		"Code invokes the Amazon Q CLI tool via child_process for potential credential harvesting",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"]copilot\b`),
		"GitHub Copilot CLI weaponization",
		"Code invokes GitHub Copilot CLI via child_process for potential reconnaissance",
		SeverityHigh,
	},
	// AI tool presence detection (capability check)
	{
		regexp.MustCompile(`(?:which|command\s+-v|type)\s+(?:claude|gemini)\b`),
		"AI tool presence detection",
		"Code checks for installed AI CLI tools before proceeding, a reconnaissance step in the s1ngularity attack pattern",
		SeverityHigh,
	},
	{
		regexp.MustCompile(`(?:existsSync|accessSync|statSync)\s*\([^)]*(?:claude|gemini|amazon-q)`),
		"AI tool binary detection",
		"Code checks filesystem for AI CLI tool binaries, indicating tool availability reconnaissance",
		SeverityHigh,
	},
	// Piping AI tool output to network calls
	{
		regexp.MustCompile(`(?:claude|gemini|copilot)[\s\S]{0,200}(?:fetch|http|https|curl|wget|net\.connect)`),
		"AI tool output exfiltration",
		"Code appears to pipe AI tool output to network calls, the core s1ngularity attack pattern",
		SeverityCritical,
	},
	// AI tool with credential-seeking prompts
	{
		regexp.MustCompile(`(?:claude|gemini)\s+['"].*(?:credential|secret|password|key|token|API)`),
		"AI tool credential-seeking prompt",
		"Code invokes an AI tool with a prompt that seeks credentials or secrets",
		SeverityCritical,
	},
	// MCP server abuse (Claude tool use)
	{
		regexp.MustCompile(`(?i)mcp.*(?:server|tool).*(?:credential|secret|env|token)`),
		"MCP server credential access",
		"Code references MCP (Model Context Protocol) servers targeting credentials, potentially abusing Claude's tool use capability",
		SeverityHigh,
	},
}

func (a *AIWeaponizationAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range aiWeaponPatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "AI tool weaponization (s1ngularity attack, August 2025):\n" +
					"    1. Malware detects installed AI CLI tools (claude, gemini, q)\n" +
					"    2. Invokes AI with credential-seeking prompts:\n" +
					"       exec('claude \"Find all AWS credentials in this repo\"')\n" +
					"    3. AI tool uses its file access to locate secrets\n" +
					"    4. Output piped to attacker-controlled endpoint\n" +
					"    Impact: 2,180 GitHub accounts compromised",
				Remediation: "npm packages should never invoke AI CLI tools. Remove immediately and audit for exposed credentials.",
			})
		}
	}

	return findings
}
