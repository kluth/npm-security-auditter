package analyzer

import (
	"testing"
)

func TestPrivateNetworkAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
		severity Severity
	}{
		{
			"AWS Metadata API access",
			"fetch('http://169.254.169.254/latest/meta-data/')",
			"Private network access detected",
			SeverityCritical,
		},
		{
			"Localhost access",
			"axios.get('http://localhost:8080/config')",
			"Private network access detected",
			SeverityHigh,
		},
		{
			"Private IP range",
			"const internal = '192.168.1.50';",
			"Private network access detected",
			SeverityHigh,
		},
		{
			"Public API access",
			"const api = 'https://api.github.com';",
			"",
			0,
		},
	}

	analyzer := NewPrivateNetworkAnalyzer()
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
