package analyzer

import (
	"context"
	"testing"

	"github.com/matthias/auditter/internal/registry"
)

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
