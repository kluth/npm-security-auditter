package analyzer

import (
	"testing"

	"github.com/kluth/npm-security-auditter/internal/tarball"
)

func TestLockfileAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		files    []tarball.FileEntry
		contents map[string]string // Mock file contents
		expected string
		severity Severity
	}{
		{
			"Malicious Resolved URL",
			[]tarball.FileEntry{{Path: "package-lock.json"}},
			map[string]string{
				"package-lock.json": `{
					"dependencies": {
						"lodash": {
							"version": "4.17.21",
							"resolved": "https://evil.com/lodash.tgz",
							"integrity": "sha512-..."
						}
					}
				}`,
			},
			"Suspicious lockfile registry URL",
			SeverityCritical,
		},
		{
			"Insecure HTTP URL",
			[]tarball.FileEntry{{Path: "package-lock.json"}},
			map[string]string{
				"package-lock.json": `{
					"dependencies": {
						"safe": {
							"version": "1.0.0",
							"resolved": "http://registry.npmjs.org/safe.tgz",
							"integrity": "sha512-..."
						}
					}
				}`,
			},
			"Insecure HTTP registry URL",
			SeverityMedium,
		},
		{
			"Safe Lockfile",
			[]tarball.FileEntry{{Path: "package-lock.json"}},
			map[string]string{
				"package-lock.json": `{
					"dependencies": {
						"safe": {
							"version": "1.0.0",
							"resolved": "https://registry.npmjs.org/safe/-/safe-1.0.0.tgz",
							"integrity": "sha512-..."
						}
					}
				}`,
			},
			"",
			0,
		},
	}

	analyzer := NewLockfileAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock extraction by attaching content directly to the test
			// We'll need to mock the file reading part or just pass the map to a helper method in the analyzer
			// For TDD, let's expose a scanLockfile method that takes bytes
			findings := analyzer.scanLockfile([]byte(tt.contents["package-lock.json"]))

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
