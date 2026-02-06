package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestCommunityTrustAnalyzer_Name(t *testing.T) {
	a := NewCommunityTrustAnalyzer()
	if a.Name() != "community-trust" {
		t.Errorf("expected name 'community-trust', got %q", a.Name())
	}
}

func TestCommunityTrustAnalyzer_NoRepo(t *testing.T) {
	a := NewCommunityTrustAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{Name: "test-pkg", Version: "1.0.0"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	// Should flag missing repository
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "repository") || strings.Contains(f.Title, "Repository") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for missing repository URL")
	}
}

func TestCommunityTrustAnalyzer_NoLicense(t *testing.T) {
	a := NewCommunityTrustAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Repository: &registry.Repository{
			URL: "https://github.com/user/repo",
		},
	}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		License: "",
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "license") || strings.Contains(f.Title, "License") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for missing license")
	}
}

func TestCommunityTrustAnalyzer_NoDescription(t *testing.T) {
	a := NewCommunityTrustAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Repository: &registry.Repository{
			URL: "https://github.com/user/repo",
		},
	}
	version := &registry.PackageVersion{
		Name:        "test-pkg",
		Version:     "1.0.0",
		License:     "MIT",
		Description: "",
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "description") || strings.Contains(f.Title, "Description") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for missing description")
	}
}

func TestCommunityTrustAnalyzer_SingleMaintainer(t *testing.T) {
	a := NewCommunityTrustAnalyzer()
	ctx := context.Background()
	now := time.Now()
	pkg := &registry.PackageMetadata{
		Name: "popular-pkg",
		Repository: &registry.Repository{
			URL: "https://github.com/user/repo",
		},
		Maintainers: []registry.Maintainer{
			{Name: "solo-dev", Email: "solo@example.com"},
		},
		Time: map[string]time.Time{
			"created": now.Add(-365 * 24 * time.Hour),
		},
		// Many versions = well-used package
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {}, "1.1.0": {}, "1.2.0": {},
			"2.0.0": {}, "2.1.0": {}, "3.0.0": {},
		},
	}
	version := &registry.PackageVersion{
		Name:    "popular-pkg",
		Version: "3.0.0",
		License: "MIT",
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Single maintainer") || strings.Contains(f.Title, "single maintainer") || strings.Contains(f.Title, "bus factor") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for single maintainer on established package")
	}
}

func TestCommunityTrustAnalyzer_NoReadme(t *testing.T) {
	a := NewCommunityTrustAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Repository: &registry.Repository{
			URL: "https://github.com/user/repo",
		},
		Readme: "",
	}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		License: "MIT",
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "README") || strings.Contains(f.Title, "readme") || strings.Contains(f.Title, "documentation") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for missing README")
	}
}

func TestCommunityTrustAnalyzer_HealthyPackage(t *testing.T) {
	a := NewCommunityTrustAnalyzer()
	ctx := context.Background()
	now := time.Now()
	pkg := &registry.PackageMetadata{
		Name:        "healthy-pkg",
		Description: "A well-maintained package",
		Repository: &registry.Repository{
			URL: "https://github.com/org/healthy-pkg",
		},
		Maintainers: []registry.Maintainer{
			{Name: "dev1", Email: "dev1@company.com"},
			{Name: "dev2", Email: "dev2@company.com"},
		},
		Time: map[string]time.Time{
			"created": now.Add(-365 * 24 * time.Hour),
		},
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {}, "2.0.0": {},
		},
		Readme: "# Healthy Package\n\nA well-documented package with proper README.",
	}
	version := &registry.PackageVersion{
		Name:        "healthy-pkg",
		Version:     "2.0.0",
		License:     "MIT",
		Description: "A well-maintained package",
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity for healthy package: %s", f.Title)
		}
	}
}
