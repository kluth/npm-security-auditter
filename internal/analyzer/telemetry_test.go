package analyzer

import (
	"testing"
)

func TestTelemetryAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
		severity Severity
	}{
		{
			"Google Analytics",
			"https://www.google-analytics.com/collect?v=1...",
			"Telemetry/Analytics detected",
			SeverityMedium,
		},
		{
			"Segment.io",
			"import { Analytics } from '@segment/analytics-node';",
			"Telemetry/Analytics detected",
			SeverityMedium,
		},
		{
			"Generic telemetry call",
			"this.telemetry.track('event');",
			"Telemetry/Analytics detected",
			SeverityLow,
		},
		{
			"Safe code",
			"const x = 1;",
			"",
			0,
		},
	}

	analyzer := NewTelemetryAnalyzer()
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
