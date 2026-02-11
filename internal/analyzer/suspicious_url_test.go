package analyzer

import (
	"testing"
)

func TestSuspiciousURLAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
		severity Severity
	}{
		{
			"Likely DGA domain",
			"https://vjq82bmx9p1zc4l0.example.net/c2",
			"Suspicious URL/Domain detected",
			SeverityHigh,
		},
		{
			"IP-based URL",
			"http://1.2.3.4:5678/payload",
			"Suspicious URL/Domain detected",
			SeverityHigh,
		},
		{
			"Legitimate long URL",
			"https://very-long-but-readable-domain-name-that-is-fine.com/api",
			"",
			0,
		},
	}

	analyzer := NewSuspiciousURLAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzer.scanContent(tt.content, "index.js")

			if tt.expected == "" {
				if len(findings) > 0 {
					t.Errorf("expected 0 findings, got %d", len(findings))
				}
				return
			}

			found := false
			for _, f := range findings {
				if f.Severity == tt.severity {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected finding with severity %v, got %+v", tt.severity, findings)
			}
		})
	}
}
