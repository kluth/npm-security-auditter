package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestMaintainerAnalyzer_VersionMaintainerOverride(t *testing.T) {
	analyzer := NewMaintainerAnalyzer()
	pkg := &registry.PackageMetadata{
		Maintainers: []registry.Maintainer{{Name: "user1", Email: "user@example.com"}},
	}
	ver := &registry.PackageVersion{
		Maintainers: []registry.Maintainer{
			{Name: "v1", Email: "v1@company.com"},
			{Name: "v2", Email: "v2@company.com"},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	// Version maintainers override pkg maintainers. 2 maintainers with good emails -> 0 findings.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with version maintainers, got %d: %+v", len(findings), findings)
	}
}

func TestMaintainerAnalyzer_PublishAnomalies(t *testing.T) {
	analyzer := NewMaintainerAnalyzer()
	now := time.Now()
	pkg := &registry.PackageMetadata{
		Maintainers: []registry.Maintainer{
			{Name: "u1", Email: "u1@co.com"},
			{Name: "u2", Email: "u2@co.com"},
		},
		Time: map[string]time.Time{
			"created":  now.Add(-3 * 365 * 24 * time.Hour), // created 3 years ago
			"modified": now.Add(-5 * 24 * time.Hour),       // modified 5 days ago
			"1.0.0":    now.Add(-2 * 365 * 24 * time.Hour), // published 2 years ago
			"1.0.1":    now.Add(-5 * 24 * time.Hour),       // recent (within 30 days)
		},
	}
	ver := &registry.PackageVersion{}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "Sudden activity after long inactivity" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Sudden activity after long inactivity' finding")
	}
}

func TestMaintainerAnalyzer_PublishAnomaliesNoActivity(t *testing.T) {
	// Not enough publish times to trigger
	analyzer := NewMaintainerAnalyzer()
	pkg := &registry.PackageMetadata{
		Maintainers: []registry.Maintainer{
			{Name: "u1", Email: "u1@co.com"},
			{Name: "u2", Email: "u2@co.com"},
		},
		Time: map[string]time.Time{
			"created":  time.Now().Add(-365 * 24 * time.Hour),
			"modified": time.Now().Add(-365 * 24 * time.Hour),
		},
	}
	ver := &registry.PackageVersion{}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Title == "Sudden activity after long inactivity" {
			t.Error("should not report sudden activity without enough publish times")
		}
	}
}

func TestMaintainerAnalyzer_EmptyTime(t *testing.T) {
	analyzer := NewMaintainerAnalyzer()
	pkg := &registry.PackageMetadata{
		Maintainers: []registry.Maintainer{
			{Name: "u1", Email: "u1@co.com"},
			{Name: "u2", Email: "u2@co.com"},
		},
		Time: map[string]time.Time{},
	}
	ver := &registry.PackageVersion{}

	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty time, got %d", len(findings))
	}
}

func TestMaintainerAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		maintainers  []registry.Maintainer
		wantFindings int
		wantTitle    string
	}{
		{
			name:         "no maintainers",
			maintainers:  nil,
			wantFindings: 1,
			wantTitle:    "No maintainers listed",
		},
		{
			name:         "single maintainer",
			maintainers:  []registry.Maintainer{{Name: "user1", Email: "user@example.com"}},
			wantFindings: 1,
			wantTitle:    "Single maintainer",
		},
		{
			name: "multiple maintainers with good emails",
			maintainers: []registry.Maintainer{
				{Name: "user1", Email: "user1@company.com"},
				{Name: "user2", Email: "user2@company.com"},
			},
			wantFindings: 0,
		},
		{
			name: "disposable email",
			maintainers: []registry.Maintainer{
				{Name: "user1", Email: "user@mailinator.com"},
				{Name: "user2", Email: "user2@company.com"},
			},
			wantFindings: 1, // disposable email finding only (multiple maintainers)
			wantTitle:    "Disposable email domain",
		},
	}

	analyzer := NewMaintainerAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := &registry.PackageMetadata{
				Maintainers: tt.maintainers,
			}
			ver := &registry.PackageVersion{}

			findings, err := analyzer.Analyze(context.Background(), pkg, ver)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("Analyze() returned %d findings, want %d. Findings: %+v", len(findings), tt.wantFindings, findings)
			}
			if tt.wantFindings > 0 && findings[0].Title != tt.wantTitle {
				t.Errorf("findings[0].Title = %q, want %q", findings[0].Title, tt.wantTitle)
			}
		})
	}
}
