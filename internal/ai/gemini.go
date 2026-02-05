package ai

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// GeminiPrompt is the system prompt for the Gemini AI analysis.
const GeminiPrompt = `You are a security analyst reviewing npm package audit results. Analyze the JSON audit report and provide a concise security assessment.

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

// GenerateSummary invokes the Gemini CLI to analyze the audit report JSON.
// It returns the AI-generated summary or an error if the CLI is not available.
func GenerateSummary(reportJSON []byte) (string, error) {
	// Check if gemini CLI is available
	_, err := exec.LookPath("gemini")
	if err != nil {
		return "", fmt.Errorf("gemini CLI not found: %w (install with: pip install google-generativeai)", err)
	}

	// Prepare the full prompt with the JSON data
	fullPrompt := GeminiPrompt + "\n\nAudit Report JSON:\n" + string(reportJSON)

	// Execute gemini CLI
	cmd := exec.Command("gemini", "-p", fullPrompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		errMsg := stderr.String()
		if errMsg != "" {
			return "", fmt.Errorf("gemini CLI error: %s", strings.TrimSpace(errMsg))
		}
		return "", fmt.Errorf("gemini CLI failed: %w", err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// IsAvailable checks if the Gemini CLI is installed and accessible.
func IsAvailable() bool {
	_, err := exec.LookPath("gemini")
	return err == nil
}
