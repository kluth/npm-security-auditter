package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/tarball"
)

func TestDangerousExtensionAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		files    []tarball.FileEntry
		expected string
		severity Severity
	}{
		{
			"Windows Executable",
			[]tarball.FileEntry{{Path: "bin/malware.exe"}},
			"Dangerous file extension detected",
			SeverityCritical,
		},
		{
			"Shell Script",
			[]tarball.FileEntry{{Path: "setup.sh"}},
			"Dangerous file extension detected",
			SeverityHigh,
		},
		{
			"Python Script",
			[]tarball.FileEntry{{Path: "script.py"}},
			"Suspicious file extension detected",
			SeverityMedium,
		},
		{
			"Safe Files",
			[]tarball.FileEntry{{Path: "index.js"}, {Path: "README.md"}},
			"",
			0,
		},
	}

	analyzer := NewDangerousExtensionAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &tarball.ExtractedPackage{Files: tt.files}
			findings, err := analyzer.AnalyzePackage(context.Background(), ep)
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
