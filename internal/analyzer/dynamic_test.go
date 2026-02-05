package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/sandbox"
)

func TestSandboxAnalyzer_Name(t *testing.T) {
	a := NewSandboxAnalyzer()
	if a.Name() != "dynamic-analysis" {
		t.Errorf("expected name 'dynamic-analysis', got %q", a.Name())
	}
}

func TestSandboxAnalyzer_Constructor(t *testing.T) {
	a := NewSandboxAnalyzer()
	if a == nil {
		t.Fatal("NewSandboxAnalyzer returned nil")
	}
	if a.runner == nil {
		t.Fatal("runner is nil")
	}
}

func TestSandboxAnalyzer_Analyze(t *testing.T) {
	if !sandbox.CheckNodeAvailable() {
		t.Fatal("node/npm not available - mandatory for dynamic analysis")
	}

	// 1. Setup dummy package
	tmpDir, err := os.MkdirTemp("", "auditter-dynamic-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pkgJSON := `{"name": "test-pkg-dynamic", "version": "1.0.0", "main": "index.js"}`
	indexJS := `
const cp = require('child_process');
try { cp.execSync('ls'); } catch(e){}

const net = require('net');
try { net.connect(80, 'example.com'); } catch(e){}

const dns = require('dns');
try { dns.lookup('example.com', ()=>{}); } catch(e){}

const fs = require('fs');
try { fs.readFileSync('/etc/passwd'); } catch(e){}

try { const x = process.env.AWS_SECRET_ACCESS_KEY; const y = process.env.NPM_TOKEN; } catch(e){}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte(indexJS), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Run Analyzer
	a := NewSandboxAnalyzer()
	ctx := context.Background()
	meta := &registry.PackageMetadata{Name: "test-pkg-dynamic"}
	ver := &registry.PackageVersion{Version: "file:" + tmpDir}

	findings, err := a.Analyze(ctx, meta, ver)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// 3. Verify Findings - use the new i18n keys
	expectedTitles := map[string]bool{
		"dynamic_process_exec":     false,
		"dynamic_network_request":  false,
		"dynamic_dns_lookup":       false,
		"dynamic_sensitive_file":   false,
		"dynamic_sensitive_env":    false,
	}

	for _, f := range findings {
		if _, ok := expectedTitles[f.Title]; ok {
			expectedTitles[f.Title] = true
		}
	}

	for title, found := range expectedTitles {
		if !found {
			t.Errorf("expected finding %q not found", title)
		}
	}
}
