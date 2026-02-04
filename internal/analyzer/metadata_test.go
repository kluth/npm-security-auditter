package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestMetadataAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		pkg          *registry.PackageMetadata
		version      *registry.PackageVersion
		wantFindings int
		wantTitles   []string
	}{
		{
			name: "healthy package",
			pkg: &registry.PackageMetadata{
				Description: "A useful package",
				Repository:  &registry.Repository{URL: "https://github.com/user/repo"},
				Time:        map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
				Versions:    map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
			},
			version: &registry.PackageVersion{
				License:    "MIT",
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
			},
			wantFindings: 0,
		},
		{
			name: "no repository",
			pkg: &registry.PackageMetadata{
				Description: "A package",
				Time:        map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
				Versions:    map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
			},
			version:      &registry.PackageVersion{License: "MIT"},
			wantFindings: 1,
			wantTitles:   []string{"No repository URL"},
		},
		{
			name: "no license",
			pkg: &registry.PackageMetadata{
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
				Time:       map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
				Versions:   map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
			},
			version: &registry.PackageVersion{
				Description: "A package",
				Repository:  &registry.Repository{URL: "https://github.com/user/repo"},
			},
			wantFindings: 1,
			wantTitles:   []string{"No license specified"},
		},
		{
			name: "very new package",
			pkg: &registry.PackageMetadata{
				Description: "New pkg",
				Repository:  &registry.Repository{URL: "https://github.com/user/repo"},
				Time:        map[string]time.Time{"created": time.Now().Add(-2 * 24 * time.Hour)},
				Versions:    map[string]registry.PackageVersion{"1.0.0": {}},
			},
			version: &registry.PackageVersion{
				License:     "MIT",
				Description: "New pkg",
				Repository:  &registry.Repository{URL: "https://github.com/user/repo"},
			},
			wantFindings: 1,
			wantTitles:   []string{"Very new package"},
		},
		{
			name: "no description",
			pkg: &registry.PackageMetadata{
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
				Time:       map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
				Versions:   map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
			},
			version: &registry.PackageVersion{
				License:    "MIT",
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
			},
			wantFindings: 1,
			wantTitles:   []string{"No description"},
		},
		{
			name: "unusual repo host",
			pkg: &registry.PackageMetadata{
				Description: "A package",
				Repository:  &registry.Repository{URL: "https://my-private-git.com/repo"},
				Time:        map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
				Versions:    map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
			},
			version: &registry.PackageVersion{
				License:     "MIT",
				Description: "A package",
				Repository:  &registry.Repository{URL: "https://my-private-git.com/repo"},
			},
			wantFindings: 1,
			wantTitles:   []string{"Unusual repository host"},
		},
	}

	analyzer := NewMetadataAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := analyzer.Analyze(context.Background(), tt.pkg, tt.version)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("Analyze() returned %d findings, want %d. Findings: %+v",
					len(findings), tt.wantFindings, findings)
			}
			for i, title := range tt.wantTitles {
				if i < len(findings) && findings[i].Title != title {
					t.Errorf("findings[%d].Title = %q, want %q", i, findings[i].Title, title)
				}
			}
		})
	}
}

func TestMetadataAnalyzer_AgeChecks(t *testing.T) {
	tests := []struct {
		name         string
		age          time.Duration
		versions     int
		wantTitle    string
		wantDescPart string // for formatDuration check
	}{
		{
			name:         "hours old",
			age:          5 * time.Hour,
			versions:     1,
			wantTitle:    "Very new package",
			wantDescPart: "5 hours",
		},
		{
			name:         "new package (2 weeks)",
			age:          14 * 24 * time.Hour,
			versions:     1,
			wantTitle:    "New package",
			wantDescPart: "14 days",
		},
		{
			name:         "stale package",
			age:          60 * 24 * time.Hour,
			versions:     1,
			wantTitle:    "Stale package",
			wantDescPart: "", // checkAge doesn't use formatDuration for stale, just description text
		},
	}

	analyzer := NewMetadataAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versions := make(map[string]registry.PackageVersion)
			for i := 0; i < tt.versions; i++ {
				versions[string(rune('a'+i))] = registry.PackageVersion{}
			}

			pkg := &registry.PackageMetadata{
				Repository: &registry.Repository{URL: "http://github.com/a/b"},
				Time: map[string]time.Time{
					"created": time.Now().Add(-tt.age),
				},
				Versions: versions,
			}
			ver := &registry.PackageVersion{License: "MIT"}

			findings, err := analyzer.Analyze(context.Background(), pkg, ver)
			if err != nil {
				t.Fatal(err)
			}

			found := false
			for _, f := range findings {
				if f.Title == tt.wantTitle {
					found = true
					if tt.wantDescPart != "" && !strings.Contains(f.Description, tt.wantDescPart) {
						t.Errorf("expected description to contain %q, got %q", tt.wantDescPart, f.Description)
					}
				}
			}
			if !found {
				t.Errorf("expected finding %q", tt.wantTitle)
			}
		})
	}
}

func TestMetadataAnalyzer_MissingCreated(t *testing.T) {
	analyzer := NewMetadataAnalyzer()
	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
		Time:       map[string]time.Time{}, // Empty time map
	}
	ver := &registry.PackageVersion{License: "MIT"}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	// Should skip age check, no error, no age-related findings
	for _, f := range findings {
		if strings.Contains(f.Title, "package") { // New package, Very new package, Stale package
			t.Errorf("unexpected age finding: %s", f.Title)
		}
	}
}

func TestMetadataAnalyzer_RecentPublish(t *testing.T) {
	analyzer := NewMetadataAnalyzer()
	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
		Time: map[string]time.Time{
			"created": time.Now().Add(-365 * 24 * time.Hour),
			"1.0.0":   time.Now().Add(-1 * time.Hour), // published 1 hour ago
		},
		Versions: map[string]registry.PackageVersion{"1.0.0": {}},
	}
	ver := &registry.PackageVersion{
		Version:    "1.0.0",
		License:    "MIT",
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
	}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Very recently published version" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Very recently published version' finding")
	}
}

func TestMetadataAnalyzer_RecentPublishNotRecent(t *testing.T) {
	analyzer := NewMetadataAnalyzer()
	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
		Time: map[string]time.Time{
			"created": time.Now().Add(-365 * 24 * time.Hour),
			"1.0.0":   time.Now().Add(-48 * time.Hour), // published 2 days ago
		},
		Versions: map[string]registry.PackageVersion{"1.0.0": {}},
	}
	ver := &registry.PackageVersion{
		Version:    "1.0.0",
		License:    "MIT",
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
	}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Title == "Very recently published version" {
			t.Error("should not find 'Very recently published version' for 2 day old publish")
		}
	}
}

func TestMetadataAnalyzer_Deprecated(t *testing.T) {
	analyzer := NewMetadataAnalyzer()
	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
		Time:       map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
		Versions:   map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
	}
	ver := &registry.PackageVersion{
		License:    "MIT",
		Deprecated: "Use package-v2 instead",
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
	}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Deprecated package version" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Deprecated package version' finding")
	}
}

func TestMetadataAnalyzer_CopyleftLicense(t *testing.T) {
	analyzer := NewMetadataAnalyzer()
	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
		Time:       map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
		Versions:   map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
	}
	ver := &registry.PackageVersion{
		License:    "GPL-3.0",
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
	}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Copyleft license detected" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Copyleft license detected' finding")
	}
}

func TestMetadataAnalyzer_UnconventionalLicense(t *testing.T) {
	analyzer := NewMetadataAnalyzer()
	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
		Time:       map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
		Versions:   map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
	}
	ver := &registry.PackageVersion{
		License:    "WTFPL",
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
	}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Unconventional license" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Unconventional license' finding")
	}
}

func TestMetadataAnalyzer_EmptyRepoURL(t *testing.T) {
	analyzer := NewMetadataAnalyzer()
	pkg := &registry.PackageMetadata{
		Time:     map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
		Versions: map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
	}
	ver := &registry.PackageVersion{
		License:    "MIT",
		Repository: &registry.Repository{URL: ""},
	}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Empty repository URL" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Empty repository URL' finding")
	}
}

func TestMetadataAnalyzer_VersionDescriptionFallback(t *testing.T) {
	analyzer := NewMetadataAnalyzer()
	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "http://github.com/a/b"},
		Time:       map[string]time.Time{"created": time.Now().Add(-365 * 24 * time.Hour)},
		Versions:   map[string]registry.PackageVersion{"1.0.0": {}, "1.1.0": {}},
	}
	// version has description, pkg doesn't - should NOT trigger "No description"
	ver := &registry.PackageVersion{
		License:     "MIT",
		Description: "A valid description",
		Repository:  &registry.Repository{URL: "http://github.com/a/b"},
	}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Title == "No description" {
			t.Error("should not report 'No description' when version has description")
		}
	}
}
