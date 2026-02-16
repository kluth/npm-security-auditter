package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestScorecardAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		mockResp string
		status   int
		expected string
		severity Severity
	}{
		{
			"Dangerous Workflow",
			`{"score": 4.5, "checks": [{"name": "Dangerous-Workflow", "score": 0, "reason": "Arbitrary code execution in CI"}]}`,
			200,
			"OSSF Scorecard: Dangerous Workflow",
			SeverityCritical,
		},
		{
			"Binary Artifacts",
			`{"score": 6.0, "checks": [{"name": "Binary-Artifacts", "score": 0, "reason": "Binaries in repo"}]}`,
			200,
			"OSSF Scorecard: Binary Artifacts",
			SeverityHigh,
		},
		{
			"Low Score",
			`{"score": 2.1, "checks": []}`,
			200,
			"Low OSSF Security Score",
			SeverityMedium,
		},
		{
			"High Score",
			`{"score": 9.0, "checks": []}`,
			200,
			"",
			0,
		},
		{
			"Not Found",
			`{}`,
			404,
			"",
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.mockResp))
			}))
			defer server.Close()

			analyzer := NewScorecardAnalyzer()
			analyzer.apiURL = server.URL // Override for test

			pkg := &registry.PackageMetadata{
				Repository: &registry.Repository{URL: "https://github.com/owner/repo"},
			}

			findings, err := analyzer.Analyze(context.Background(), pkg, nil)
			if err != nil {
				if tt.status != 200 && len(findings) == 0 {
					return // Expected error/empty for non-200
				}
				t.Fatal(err)
			}

			if tt.expected == "" {
				if len(findings) > 0 {
					t.Errorf("expected 0 findings, got %d", len(findings))
				}
				return
			}

			found := false
			for _, f := range findings {
				if f.Title == tt.expected && f.Severity == tt.severity {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected finding %q with severity %v, got %+v", tt.expected, tt.severity, findings)
			}
		})
	}
}
