package ai

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// ClaudePrompt is the system prompt for the Claude AI analysis.
const ClaudePrompt = `You are a security analyst reviewing npm package audit results. Analyze the JSON audit report and provide a concise security assessment.

Format your response EXACTLY as follows:

VERDICT: [SAFE|REVIEW NEEDED|DO NOT INSTALL] - [one-line reason]

KEY RISKS:
- [risk 1, if any]
- [risk 2, if any]
- [risk 3, if any]
(Skip this section entirely if the package is safe)

RECOMMENDED ACTIONS:
- [action 1]
- [action 2]

CONTEXT:
[Note if this is a well-known package where certain findings (like minified code entropy) are expected and acceptable. Mention the package's reputation if relevant.]

Be concise and actionable. Focus on real security concerns, not informational findings.`

// ClaudeTopListPrompt is the system prompt for comparing multiple packages.
const ClaudeTopListPrompt = `You are a security architect comparing multiple npm packages in the same category. 
Analyze the audit reports for these packages and provide a ranked recommendation list.
Identify which packages are most secure and why, and which ones should be avoided.

Format your response as follows:

RANKED RECOMMENDATION (Most Secure First):
1. [Package Name] - [Brief Security Justification]
2. [Package Name] - [Brief Security Justification]
...

CRITICAL COMPARISON:
- [Comparison point 1: e.g. "Package A has many vulnerabilities while Package B is clean"]
- [Comparison point 2: e.g. "Package C has suspicious install scripts"]

FINAL ARCHITECTURAL ADVICE:
[Brief advice on which package to choose for a production environment based on the security profile.]

Be concise and focus on identifying the most production-ready, secure option.`

// GenerateClaudeSummary invokes the Claude CLI to analyze the audit report JSON.
func GenerateClaudeSummary(reportJSON []byte) (string, error) {
	return generateClaudeWithPrompt(reportJSON, ClaudePrompt)
}

// GenerateClaudeTopListSummary invokes the Claude CLI with the top list comparison prompt.
func GenerateClaudeTopListSummary(reportJSON []byte) (string, error) {
	return generateClaudeWithPrompt(reportJSON, ClaudeTopListPrompt)
}

func generateClaudeWithPrompt(reportJSON []byte, prompt string) (string, error) {
	// Check if claude CLI is available
	_, err := exec.LookPath("claude")
	if err != nil {
		return "", fmt.Errorf("claude CLI not found: %w", err)
	}

	// Prepare the full prompt with the JSON data
	fullPrompt := prompt + "\n\nAudit Report JSON:\n" + string(reportJSON)

	// Execute claude CLI with --print (-p) mode
	cmd := exec.Command("claude", "-p", fullPrompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		errMsg := stderr.String()
		if errMsg != "" {
			return "", fmt.Errorf("claude CLI error: %s", strings.TrimSpace(errMsg))
		}
		return "", fmt.Errorf("claude CLI failed: %w", err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// IsClaudeAvailable checks if the Claude CLI is installed and accessible.
func IsClaudeAvailable() bool {
	_, err := exec.LookPath("claude")
	return err == nil
}
