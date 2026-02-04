package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/tarball"
)

func TestMinifiedOnlyAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		files    []tarball.FileEntry
		expected string
		severity Severity
	}{
		{
			"Only minified files",
			[]tarball.FileEntry{
				{Path: "dist/bundle.min.js", IsJS: true, Size: 5000},
				{Path: "index.min.js", IsJS: true, Size: 2000},
			},
			"Package contains only minified/obfuscated code",
			SeverityMedium,
		},
		{
			"Mixed source and minified",
			[]tarball.FileEntry{
				{Path: "src/index.ts", IsJS: true, Size: 1000},
				{Path: "dist/index.js", IsJS: true, Size: 1000},
			},
			"",
			0,
		},
	}

	analyzer := NewMinifiedOnlyAnalyzer()
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
