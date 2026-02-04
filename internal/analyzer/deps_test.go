package analyzer

import (
	"context"
	"fmt"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestDepsAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		deps         map[string]string
		wantFindings int
	}{
		{
			name:         "no dependencies",
			deps:         nil,
			wantFindings: 0,
		},
		{
			name:         "few normal deps",
			deps:         map[string]string{"express": "^4.0.0", "lodash": "^4.17.0"},
			wantFindings: 0,
		},
		{
			name: "wildcard version",
			deps: map[string]string{"some-pkg": "*"},
			wantFindings: 1,
		},
		{
			name: "latest version",
			deps: map[string]string{"some-pkg": "latest"},
			wantFindings: 1,
		},
		{
			name: "internal-looking name",
			deps: map[string]string{"internal-utils": "^1.0.0"},
			wantFindings: 1,
		},
		{
			name: "open-ended range",
			deps: map[string]string{"some-pkg": ">=1.0.0"},
			wantFindings: 1,
		},
	}

	analyzer := NewDepsAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver := &registry.PackageVersion{Dependencies: tt.deps}
			findings, err := analyzer.Analyze(context.Background(), &registry.PackageMetadata{}, ver)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("Analyze() returned %d findings, want %d. Findings: %+v",
					len(findings), tt.wantFindings, findings)
			}
		})
	}
}

func TestDepsAnalyzerExcessive(t *testing.T) {
	deps := make(map[string]string)
	for i := 0; i < 55; i++ {
		deps[fmt.Sprintf("dep-%d", i)] = "^1.0.0"
	}

	analyzer := NewDepsAnalyzer()
	ver := &registry.PackageVersion{Dependencies: deps}
	findings, err := analyzer.Analyze(context.Background(), &registry.PackageMetadata{}, ver)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "Excessive dependencies" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'Excessive dependencies' finding")
	}
}

func TestIsInternalLookingName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"internal-utils", true},
		{"private-helpers", true},
		{"my-lib-internal", true},
		{"express", false},
		{"@scope/internal-utils", false}, // scoped is fine
		{"corp-services", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInternalLookingName(tt.name)
			if got != tt.want {
				t.Errorf("isInternalLookingName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
