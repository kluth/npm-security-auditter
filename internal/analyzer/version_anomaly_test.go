package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestVersionAnomalyAnalyzer_Name(t *testing.T) {
	a := NewVersionAnomalyAnalyzer()
	if a.Name() != "version-anomalies" {
		t.Errorf("expected name 'version-anomalies', got %q", a.Name())
	}
}

func TestVersionAnomalyAnalyzer_RapidPublishing(t *testing.T) {
	a := NewVersionAnomalyAnalyzer()
	ctx := context.Background()
	now := time.Now()

	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Time: map[string]time.Time{
			"created": now.Add(-24 * time.Hour),
			"1.0.0":   now.Add(-24 * time.Hour),
			"1.0.1":   now.Add(-23 * time.Hour),
			"1.0.2":   now.Add(-22 * time.Hour),
			"1.0.3":   now.Add(-21 * time.Hour),
			"1.0.4":   now.Add(-20 * time.Hour),
			"1.0.5":   now.Add(-19 * time.Hour),
		},
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {}, "1.0.1": {}, "1.0.2": {},
			"1.0.3": {}, "1.0.4": {}, "1.0.5": {},
		},
	}
	version := &registry.PackageVersion{Name: "test-pkg", Version: "1.0.5"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Rapid") || strings.Contains(f.Title, "rapid") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for rapid version publishing")
	}
}

func TestVersionAnomalyAnalyzer_MajorVersionJump(t *testing.T) {
	a := NewVersionAnomalyAnalyzer()
	ctx := context.Background()
	now := time.Now()

	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Time: map[string]time.Time{
			"created": now.Add(-365 * 24 * time.Hour),
			"1.0.0":   now.Add(-365 * 24 * time.Hour),
			"1.0.1":   now.Add(-300 * 24 * time.Hour),
			"99.0.0":  now.Add(-1 * time.Hour),
		},
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {}, "1.0.1": {}, "99.0.0": {},
		},
	}
	version := &registry.PackageVersion{Name: "test-pkg", Version: "99.0.0"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "version jump") || strings.Contains(f.Title, "Version jump") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for major version jump from 1.x to 99.x")
	}
}

func TestVersionAnomalyAnalyzer_VersionZeroZeroOne(t *testing.T) {
	a := NewVersionAnomalyAnalyzer()
	ctx := context.Background()
	now := time.Now()

	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Time: map[string]time.Time{
			"created": now.Add(-1 * time.Hour),
			"0.0.1":   now.Add(-1 * time.Hour),
		},
		Versions: map[string]registry.PackageVersion{
			"0.0.1": {},
		},
	}
	version := &registry.PackageVersion{Name: "test-pkg", Version: "0.0.1"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "single version") || strings.Contains(f.Title, "Single version") || strings.Contains(f.Title, "0.0.1") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for single version 0.0.1 package")
	}
}

func TestVersionAnomalyAnalyzer_GapInVersionHistory(t *testing.T) {
	a := NewVersionAnomalyAnalyzer()
	ctx := context.Background()
	now := time.Now()

	// Package was dormant for years then suddenly got a new version
	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Time: map[string]time.Time{
			"created": now.Add(-3 * 365 * 24 * time.Hour),
			"1.0.0":   now.Add(-3 * 365 * 24 * time.Hour),
			"1.0.1":   now.Add(-2 * 365 * 24 * time.Hour),
			"1.0.2":   now.Add(-1 * time.Hour),
		},
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {}, "1.0.1": {}, "1.0.2": {},
		},
	}
	version := &registry.PackageVersion{Name: "test-pkg", Version: "1.0.2"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "dormant") || strings.Contains(f.Title, "Dormant") || strings.Contains(f.Title, "gap") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for dormant package suddenly updated")
	}
}

func TestVersionAnomalyAnalyzer_NormalPackage(t *testing.T) {
	a := NewVersionAnomalyAnalyzer()
	ctx := context.Background()
	now := time.Now()

	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Time: map[string]time.Time{
			"created": now.Add(-365 * 24 * time.Hour),
			"1.0.0":   now.Add(-365 * 24 * time.Hour),
			"1.1.0":   now.Add(-300 * 24 * time.Hour),
			"1.2.0":   now.Add(-200 * 24 * time.Hour),
			"2.0.0":   now.Add(-100 * 24 * time.Hour),
			"2.1.0":   now.Add(-30 * 24 * time.Hour),
		},
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {}, "1.1.0": {}, "1.2.0": {},
			"2.0.0": {}, "2.1.0": {},
		},
	}
	version := &registry.PackageVersion{Name: "test-pkg", Version: "2.1.0"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity for normal package: %s", f.Title)
		}
	}
}

func TestVersionAnomalyAnalyzer_UnpublishedVersions(t *testing.T) {
	a := NewVersionAnomalyAnalyzer()
	ctx := context.Background()
	now := time.Now()

	// Time has entries for versions that don't exist in Versions map (unpublished)
	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Time: map[string]time.Time{
			"created": now.Add(-30 * 24 * time.Hour),
			"1.0.0":   now.Add(-30 * 24 * time.Hour),
			"1.0.1":   now.Add(-25 * 24 * time.Hour),
			"1.0.2":   now.Add(-20 * 24 * time.Hour),
			"1.0.3":   now.Add(-15 * 24 * time.Hour),
			"2.0.0":   now.Add(-1 * time.Hour),
		},
		Versions: map[string]registry.PackageVersion{
			// 1.0.1, 1.0.2, 1.0.3 were unpublished
			"1.0.0": {},
			"2.0.0": {},
		},
	}
	version := &registry.PackageVersion{Name: "test-pkg", Version: "2.0.0"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "unpublished") || strings.Contains(f.Title, "Unpublished") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for unpublished versions")
	}
}
