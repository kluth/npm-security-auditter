package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestStarjackingAnalyzer_Name(t *testing.T) {
	a := NewStarjackingAnalyzer()
	if a.Name() != "starjacking" {
		t.Errorf("expected name 'starjacking', got %q", a.Name())
	}
}

func TestStarjackingAnalyzer_NoRepo(t *testing.T) {
	a := NewStarjackingAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{Name: "test-pkg", Version: "1.0.0"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}
	// No repo = no starjacking check possible
	_ = findings
}

func TestStarjackingAnalyzer_DetectMismatch(t *testing.T) {
	a := NewStarjackingAnalyzer()

	// Package created yesterday pointing to an old popular repo
	findings := a.analyzeStarjacking(
		"evil-lodash",
		time.Now().Add(-24*time.Hour),
		time.Now().Add(-5*365*24*time.Hour), // repo created 5 years ago
		15000,           // lots of stars
		50,              // many forks
		"lodash/lodash", // pointing to famous repo
	)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Star-jacking") || strings.Contains(f.Title, "star") {
			found = true
			if f.Severity < SeverityHigh {
				t.Errorf("Expected HIGH+ severity for star-jacking, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected star-jacking detection for new package pointing to old popular repo")
	}
}

func TestStarjackingAnalyzer_NewPackagePopularRepo(t *testing.T) {
	a := NewStarjackingAnalyzer()

	// Very new package pointing to repo with high stars
	findings := a.analyzeStarjacking(
		"new-pkg",
		time.Now().Add(-2*24*time.Hour),     // created 2 days ago
		time.Now().Add(-3*365*24*time.Hour), // repo created 3 years ago
		5000,
		100,
		"someone/popular-repo",
	)

	found := false
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected HIGH finding for new package with popular repo")
	}
}

func TestStarjackingAnalyzer_LegitimatePackage(t *testing.T) {
	a := NewStarjackingAnalyzer()

	// Package and repo created around the same time, modest stars
	findings := a.analyzeStarjacking(
		"my-tool",
		time.Now().Add(-365*24*time.Hour),
		time.Now().Add(-400*24*time.Hour),
		50,
		5,
		"user/my-tool",
	)

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity for legitimate package: %s", f.Title)
		}
	}
}

func TestStarjackingAnalyzer_RepoNameMismatch(t *testing.T) {
	a := NewStarjackingAnalyzer()

	// Package name has zero relation to repo name
	findings := a.analyzeStarjacking(
		"totally-different-name",
		time.Now().Add(-7*24*time.Hour),
		time.Now().Add(-365*24*time.Hour),
		1000,
		50,
		"famous-org/famous-project",
	)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "mismatch") || strings.Contains(f.Title, "Mismatch") || strings.Contains(f.Title, "Star-jacking") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for package name / repo name mismatch")
	}
}
