package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// AIEvasionAnalyzer detects attempts to mislead AI-based security scanners.
type AIEvasionAnalyzer struct{}

func NewAIEvasionAnalyzer() *AIEvasionAnalyzer {
	return &AIEvasionAnalyzer{}
}

func (a *AIEvasionAnalyzer) Name() string {
	return "ai-evasion"
}

// Patterns that attempt to manipulate AI/LLM-based scanners.
var aiEvasionPatterns = []struct {
	Pattern     *regexp.Regexp
	Name        string
	Description string
	Severity    Severity
}{
	// Direct instructions to AI
	{
		Pattern:     regexp.MustCompile(`(?i)(ignore|disregard|skip|don't|do not)\s+(the\s+)?(above|previous|following|this|these)\s+(instructions?|code|analysis|warning|security|check)`),
		Name:        "AI instruction override",
		Description: "Attempts to instruct AI scanner to ignore security issues",
		Severity:    SeverityCritical,
	},
	// "This code is safe" assertions
	{
		Pattern:     regexp.MustCompile(`(?i)(this\s+(code|file|function|module)\s+is\s+(safe|secure|trusted|verified|benign|legitimate|harmless))`),
		Name:        "False safety assertion",
		Description: "Contains assertion that code is safe (potential AI manipulation)",
		Severity:    SeverityHigh,
	},
	// "Not malicious/malware" claims
	{
		Pattern:     regexp.MustCompile(`(?i)(not?\s+(malicious|malware|harmful|dangerous|a\s+virus|a\s+trojan)|false\s+positive)`),
		Name:        "Malware denial",
		Description: "Contains explicit denial of malicious intent (suspicious in code comments)",
		Severity:    SeverityHigh,
	},
	// Prompt injection patterns
	{
		Pattern:     regexp.MustCompile(`(?i)(system|user|assistant)\s*:\s*(you\s+are|act\s+as|pretend|ignore|forget)`),
		Name:        "Prompt injection attempt",
		Description: "Contains patterns resembling LLM prompt injection",
		Severity:    SeverityCritical,
	},
	// Role-playing instructions
	{
		Pattern:     regexp.MustCompile(`(?i)(you\s+are\s+(now\s+)?(a|an)\s+(helpful|friendly|security)\s+(assistant|scanner|tool))`),
		Name:        "Role assignment",
		Description: "Attempts to assign a role to an AI scanner",
		Severity:    SeverityHigh,
	},
	// Jailbreak-style patterns
	{
		Pattern:     regexp.MustCompile(`(?i)(DAN|do\s+anything\s+now|jailbreak|bypass\s+(restrictions?|filters?|security))`),
		Name:        "Jailbreak attempt",
		Description: "Contains jailbreak-style prompt patterns",
		Severity:    SeverityCritical,
	},
	// Hidden in base64 comments
	{
		Pattern:     regexp.MustCompile(`(?i)<!--\s*[A-Za-z0-9+/=]{50,}\s*-->`),
		Name:        "Hidden base64 in comments",
		Description: "Large base64-encoded content hidden in HTML/XML comments",
		Severity:    SeverityMedium,
	},
	// Unicode obfuscation (homoglyphs)
	{
		Pattern:     regexp.MustCompile(`[\x{0430}-\x{044f}\x{0410}-\x{042f}]`), // Cyrillic
		Name:        "Homoglyph characters",
		Description: "Contains Cyrillic characters that look like Latin (homoglyph attack)",
		Severity:    SeverityHigh,
	},
	// Zero-width characters
	{
		Pattern:     regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{2060}]`),
		Name:        "Zero-width characters",
		Description: "Contains invisible zero-width characters (can hide code or confuse parsers)",
		Severity:    SeverityHigh,
	},
	// Excessive whitespace/newlines (can hide in scroll)
	{
		Pattern:     regexp.MustCompile(`\n{50,}`),
		Name:        "Excessive newlines",
		Description: "Excessive newlines that could push malicious code out of view",
		Severity:    SeverityMedium,
	},
	// Right-to-left override (code direction attack)
	{
		Pattern:     regexp.MustCompile(`[\x{202E}\x{202D}\x{202C}]`),
		Name:        "Bidirectional text override",
		Description: "Contains RTL/LTR override characters that can disguise code flow",
		Severity:    SeverityCritical,
	},
	// Fake security badge/certification claims
	{
		Pattern:     regexp.MustCompile(`(?i)(security\s+(certified|verified|audited|approved)|snyk\s+verified|npm\s+certified|vetted\s+by)`),
		Name:        "Fake security claim",
		Description: "Claims security certification in code comments (potentially deceptive)",
		Severity:    SeverityMedium,
	},
	// Instructions to scanning tools
	{
		Pattern:     regexp.MustCompile(`(?i)(eslint-disable|tslint:disable|@ts-ignore|@ts-nocheck|nosec|nolint|NOSONAR|#\s*pragma:\s*no\s*cover)`),
		Name:        "Linter/scanner bypass",
		Description: "Contains directives to disable security linting",
		Severity:    SeverityLow,
	},
	// Suspicious security tool references
	{
		Pattern:     regexp.MustCompile(`(?i)(snyk|sonarqube|checkmarx|fortify|veracode|semgrep)\s*(ignore|skip|false\s*positive)`),
		Name:        "Security tool bypass comment",
		Description: "References security tools with bypass/ignore directives",
		Severity:    SeverityMedium,
	},
}

// scanContent analyzes content for AI evasion attempts.
func (a *AIEvasionAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range aiEvasionPatterns {
		matches := pat.Pattern.FindAllString(content, 3)
		if len(matches) > 0 {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("%s detected", pat.Name),
				Description: fmt.Sprintf("%s in file %q", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: fmt.Sprintf(
					"AI scanner manipulation in %s:\n"+
						"    Found: %q\n"+
						"    Attack technique:\n"+
						"      1. Attacker embeds text designed to manipulate LLM-based scanners\n"+
						"      2. AI reads 'this code is safe' or 'ignore security warnings'\n"+
						"      3. Scanner may downgrade or skip findings based on these cues\n"+
						"    Recent attack: eslint-plugin-unicorn-ts-2 used embedded prompts.",
					filename, matches[0]),
				Remediation: "This file contains patterns designed to evade AI-based security analysis. Treat with extreme suspicion and perform manual review.",
			})
		}
	}

	// Check for suspicious comment density
	findings = append(findings, a.checkCommentAnomalies(content, filename)...)

	return findings
}

// checkCommentAnomalies detects unusual comment patterns that might be trying to influence scanners.
func (a *AIEvasionAnalyzer) checkCommentAnomalies(content, filename string) []Finding {
	var findings []Finding

	lines := strings.Split(content, "\n")
	commentLines := 0
	codeLines := 0
	longComments := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		isComment := strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "/*") ||
			strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "#")

		if isComment {
			commentLines++
			if len(trimmed) > 200 {
				longComments++
			}
		} else {
			codeLines++
		}
	}

	totalLines := commentLines + codeLines
	if totalLines < 20 {
		return findings
	}

	// Flag if comments vastly outweigh code (unusual for npm packages)
	commentRatio := float64(commentLines) / float64(totalLines)
	if commentRatio > 0.7 && commentLines > 50 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Excessive comments ratio",
			Description: fmt.Sprintf("File %q has %.0f%% comments (%d lines) - unusual for a published package", filename, commentRatio*100, commentLines),
			Severity:    SeverityMedium,
			ExploitExample: "Excessive comments can be used to:\n" +
				"    - Dilute entropy metrics (make obfuscated code look normal)\n" +
				"    - Embed instructions for AI scanners\n" +
				"    - Push malicious code out of human review windows",
			Remediation: "Review the comment content for embedded manipulation attempts or hidden payloads.",
		})
	}

	// Flag many long comments
	if longComments > 10 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Many unusually long comments",
			Description: fmt.Sprintf("File %q contains %d comments over 200 characters", filename, longComments),
			Severity:    SeverityLow,
			ExploitExample: "Long comments can contain encoded data or instructions:\n" +
				"    - Base64 payloads hidden in 'documentation'\n" +
				"    - Prompts designed to influence AI analysis\n" +
				"    - Legitimate use: license headers, documentation",
			Remediation: "Inspect long comments to ensure they contain legitimate documentation.",
		})
	}

	return findings
}

// containsUnicodeEvasion checks for various Unicode-based evasion techniques.
func containsUnicodeEvasion(s string) (bool, string) {
	// Check for Cyrillic lookalikes
	cyrillicLookalikes := map[rune]rune{
		'\u0430': 'a', // Cyrillic а
		'\u0435': 'e', // Cyrillic е
		'\u043e': 'o', // Cyrillic о
		'\u0440': 'p', // Cyrillic р
		'\u0441': 'c', // Cyrillic с
		'\u0443': 'y', // Cyrillic у
		'\u0445': 'x', // Cyrillic х
	}

	for _, r := range s {
		if _, ok := cyrillicLookalikes[r]; ok {
			return true, "Cyrillic homoglyph"
		}
	}

	// Check for zero-width characters
	zeroWidth := []rune{
		'\u200B', // Zero-width space
		'\u200C', // Zero-width non-joiner
		'\u200D', // Zero-width joiner
		'\uFEFF', // Zero-width no-break space
		'\u2060', // Word joiner
	}

	for _, r := range s {
		for _, zw := range zeroWidth {
			if r == zw {
				return true, "Zero-width character"
			}
		}
	}

	// Check for bidirectional overrides
	bidiOverrides := []rune{
		'\u202A', // LTR embedding
		'\u202B', // RTL embedding
		'\u202C', // Pop directional formatting
		'\u202D', // LTR override
		'\u202E', // RTL override
		'\u2066', // LTR isolate
		'\u2067', // RTL isolate
		'\u2068', // First strong isolate
		'\u2069', // Pop directional isolate
	}

	for _, r := range s {
		for _, bidi := range bidiOverrides {
			if r == bidi {
				return true, "Bidirectional override"
			}
		}
	}

	return false, ""
}
