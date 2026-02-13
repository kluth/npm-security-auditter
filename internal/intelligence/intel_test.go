package intelligence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestManager_MaliciousPackage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "auditter-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	m := NewManager(tempDir)
	m.data.Issues = []IntelIssue{
		{
			ID:          "MAL-test-pkg",
			Type:        IssueTypeMaliciousPackage,
			Target:      "test-pkg",
			Description: "malicious test package",
			Severity:    analyzer.SeverityCritical,
		},
	}

	found, res := m.IsMaliciousPackage("test-pkg")
	if !found {
		t.Error("Expected to find malicious package test-pkg")
	}
	if res.Description != "malicious test package" {
		t.Errorf("Expected description 'malicious test package', got %q", res.Description)
	}

	found, _ = m.IsMaliciousPackage("safe-pkg")
	if found {
		t.Error("Expected not to find safe-pkg as malicious")
	}
}

func TestIntelAnalyzer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "auditter-intel-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	m := NewManager(tempDir)
	m.data.Issues = []IntelIssue{
		{
			ID:          "MAL-evil-pkg",
			Type:        IssueTypeMaliciousPackage,
			Target:      "evil-pkg",
			Description: "confirmed malware",
			Severity:    analyzer.SeverityCritical,
		},
	}

	a := analyzer.NewIntelAnalyzer(m)
	pkg := &registry.PackageMetadata{Name: "evil-pkg"}
	ver := &registry.PackageVersion{Version: "1.0.0"}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != "Known Malicious Package" {
		t.Errorf("Expected title 'Known Malicious Package', got %q", findings[0].Title)
	}
	if findings[0].Severity != analyzer.SeverityCritical {
		t.Errorf("Expected severity CRITICAL, got %v", findings[0].Severity)
	}

	// Test safe package
	pkgSafe := &registry.PackageMetadata{Name: "safe-pkg"}
	findingsSafe, _ := a.Analyze(context.Background(), pkgSafe, ver)
	if len(findingsSafe) != 0 {
		t.Errorf("Expected 0 findings for safe-pkg, got %d", len(findingsSafe))
	}
}

func TestGitHubProvider_Fetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name": "evil-pkg", "description": "stolen credentials", "severity": "critical"}]`))
	}))
	defer ts.Close()

	p := NewGitHubProvider(ts.URL)
	issues, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if len(issues) != 1 {
		t.Fatalf("Expected 1 issue, got %d", len(issues))
	}
	if issues[0].Target != "evil-pkg" {
		t.Errorf("Expected target evil-pkg, got %q", issues[0].Target)
	}
	if issues[0].Severity != analyzer.SeverityCritical {
		t.Errorf("Expected severity critical, got %v", issues[0].Severity)
	}
}
