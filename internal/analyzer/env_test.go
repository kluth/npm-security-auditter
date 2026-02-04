package analyzer

import (
	"testing"
)

func TestEnvAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string // Title fragment
		severity Severity
	}{
		{
			"Access to AWS Secret",
			"const key = process.env.AWS_SECRET_ACCESS_KEY;",
			"Sensitive environment variable access",
			SeverityCritical,
		},
		{
			"Access to Generic Password",
			"login(process.env.DB_PASSWORD);",
			"Sensitive environment variable access",
			SeverityHigh,
		},
		{
			"Bracket notation access",
			"const s = process.env['SECRET_TOKEN'];",
			"Sensitive environment variable access",
			SeverityHigh,
		},
		{
			"Safe env variable",
			"if (process.env.NODE_ENV === 'production') {}",
			"",
			0,
		},
	}

	analyzer := NewEnvAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulating findings through a mock or by calling the internal scanning logic
			// For TDD, we assume Analyze will scan files in the version metadata or tarball
			// Here we mock a version that has this content in a "virtual" file for testing
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
