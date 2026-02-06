package analyzer

import (
	"context"
	"strings"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestRemoteDepsAnalyzer_Name(t *testing.T) {
	a := NewRemoteDepsAnalyzer()
	if a.Name() != "remote-dependencies" {
		t.Errorf("expected name 'remote-dependencies', got %q", a.Name())
	}
}

func TestRemoteDepsAnalyzer_HTTPDependency(t *testing.T) {
	a := NewRemoteDepsAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dependencies: map[string]string{
			"lodash":   "^4.0.0",
			"evil-pkg": "http://evil.com/evil-pkg-1.0.0.tgz",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == SeverityCritical && strings.Contains(f.Title, "HTTP") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected CRITICAL finding for HTTP URL dependency")
	}
}

func TestRemoteDepsAnalyzer_HTTPSDependency(t *testing.T) {
	a := NewRemoteDepsAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dependencies: map[string]string{
			"remote-pkg": "https://github.com/user/repo/tarball/main",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Severity >= SeverityHigh && strings.Contains(f.Title, "URL") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected HIGH+ finding for HTTPS URL dependency")
	}
}

func TestRemoteDepsAnalyzer_GitDependency(t *testing.T) {
	a := NewRemoteDepsAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dependencies: map[string]string{
			"git-pkg": "git+https://github.com/user/repo.git",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Git") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for Git URL dependency")
	}
}

func TestRemoteDepsAnalyzer_GitHubShorthand(t *testing.T) {
	a := NewRemoteDepsAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dependencies: map[string]string{
			"shorthand-pkg": "user/repo",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "GitHub shorthand") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for GitHub shorthand dependency")
	}
}

func TestRemoteDepsAnalyzer_NormalDependencies(t *testing.T) {
	a := NewRemoteDepsAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dependencies: map[string]string{
			"lodash":  "^4.0.0",
			"express": "~5.0.0",
			"react":   "18.2.0",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding for normal deps: %s", f.Title)
		}
	}
}

func TestRemoteDepsAnalyzer_DevDependenciesAlsoChecked(t *testing.T) {
	a := NewRemoteDepsAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		DevDependencies: map[string]string{
			"evil-dev": "http://evil.com/dev.tgz",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "HTTP") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for HTTP URL in devDependencies")
	}
}

func TestRemoteDepsAnalyzer_FileDependency(t *testing.T) {
	a := NewRemoteDepsAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dependencies: map[string]string{
			"local-pkg": "file:../local-pkg",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "file:") || strings.Contains(f.Title, "Local") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for file: dependency in published package")
	}
}
