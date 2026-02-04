package analyzer

import (
	"context"
	"errors"
	"testing"

	"github.com/matthias/auditter/internal/registry"
)

type mockAnalyzer struct {
	name     string
	findings []Finding
	err      error
}

func (m *mockAnalyzer) Name() string { return m.name }
func (m *mockAnalyzer) Analyze(_ context.Context, _ *registry.PackageMetadata, _ *registry.PackageVersion) ([]Finding, error) {
	return m.findings, m.err
}

func TestRunAll(t *testing.T) {
	analyzers := []Analyzer{
		&mockAnalyzer{
			name: "mock-1",
			findings: []Finding{
				{Analyzer: "mock-1", Title: "Issue 1", Severity: SeverityHigh},
			},
		},
		&mockAnalyzer{
			name: "mock-2",
			findings: []Finding{
				{Analyzer: "mock-2", Title: "Issue 2", Severity: SeverityLow},
			},
		},
		&mockAnalyzer{
			name:     "mock-err",
			findings: nil,
			err:      errors.New("analysis failed"),
		},
	}

	pkg := &registry.PackageMetadata{Name: "test"}
	ver := &registry.PackageVersion{Version: "1.0.0"}

	results := RunAll(context.Background(), analyzers, pkg, ver)

	if len(results) != 3 {
		t.Fatalf("RunAll() returned %d results, want 3", len(results))
	}

	if results[0].AnalyzerName != "mock-1" || len(results[0].Findings) != 1 {
		t.Errorf("results[0] = %+v, want mock-1 with 1 finding", results[0])
	}
	if results[1].AnalyzerName != "mock-2" || len(results[1].Findings) != 1 {
		t.Errorf("results[1] = %+v, want mock-2 with 1 finding", results[1])
	}
	if results[2].Err == nil {
		t.Error("results[2].Err should not be nil")
	}
}

func TestFilterByMinSeverity(t *testing.T) {
	findings := []Finding{
		{Title: "Low", Severity: SeverityLow},
		{Title: "Med", Severity: SeverityMedium},
		{Title: "High", Severity: SeverityHigh},
		{Title: "Crit", Severity: SeverityCritical},
	}

	tests := []struct {
		name        string
		minSeverity Severity
		wantCount   int
	}{
		{"all", SeverityLow, 4},
		{"medium+", SeverityMedium, 3},
		{"high+", SeverityHigh, 2},
		{"critical only", SeverityCritical, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterByMinSeverity(findings, tt.minSeverity)
			if len(filtered) != tt.wantCount {
				t.Errorf("FilterByMinSeverity(%v) returned %d findings, want %d",
					tt.minSeverity, len(filtered), tt.wantCount)
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}
