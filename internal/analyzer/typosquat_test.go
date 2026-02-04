package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestTyposquatAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		pkgName      string
		wantFindings bool
	}{
		{"exact popular package", "express", false},
		{"typo of express", "expresss", true},
		{"typo of lodash", "lodahs", true},
		{"completely different", "my-unique-pkg-xyz-123", false},
		{"scoped popular package", "@angular/core", false},
		{"hyphen variant", "node-fetch", false}, // node-fetch is in the list
	}

	analyzer := NewTyposquatAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := &registry.PackageMetadata{Name: tt.pkgName}
			ver := &registry.PackageVersion{Version: "1.0.0"}
			findings, err := analyzer.Analyze(context.Background(), pkg, ver)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if tt.wantFindings && len(findings) == 0 {
				t.Error("Analyze() returned no findings, want at least 1")
			}
			if !tt.wantFindings && len(findings) > 0 {
				t.Errorf("Analyze() returned %d findings, want 0", len(findings))
			}
		})
	}
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"express", "expresss", 1},
		{"lodash", "lodahs", 2},
		{"kitten", "sitting", 3},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := levenshteinDistance(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("levenshteinDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestTyposquatAnalyzer_Distance2(t *testing.T) {
	// Test a package name with distance 2 from a popular package
	analyzer := NewTyposquatAnalyzer()
	pkg := &registry.PackageMetadata{Name: "lodahs"} // distance 2 from lodash
	ver := &registry.PackageVersion{Version: "1.0.0"}
	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Error("expected SeverityMedium for distance 2 typosquat")
	}
}

func TestTyposquatAnalyzer_PatternOnly(t *testing.T) {
	// Test a package that triggers pattern detection but NOT levenshtein
	analyzer := NewTyposquatAnalyzer()
	pkg := &registry.PackageMetadata{Name: "express-js"} // affix variant of express
	ver := &registry.PackageVersion{Version: "1.0.0"}
	findings, err := analyzer.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	foundPattern := false
	for _, f := range findings {
		if f.Title == "Typosquatting pattern detected" {
			foundPattern = true
		}
	}
	if !foundPattern {
		t.Error("expected typosquatting pattern finding for express-js")
	}
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"express", "express"},
		{"@scope/pkg", "pkg"},
		{"MyPkg", "mypkg"},
	}
	for _, tt := range tests {
		got := normalizeName(tt.input)
		if got != tt.want {
			t.Errorf("normalizeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDetectTyposquatPattern(t *testing.T) {
	tests := []struct {
		name    string
		pkgName string
		want    bool
	}{
		{"hyphen variant of nodefetch", "nodefetch", true},
		{"js suffix", "expressjs", true},
		{"normal name", "totally-unique-pkg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectTyposquatPattern(tt.pkgName)
			if tt.want && result == "" {
				t.Error("detectTyposquatPattern() returned empty, want pattern")
			}
			if !tt.want && result != "" {
				t.Errorf("detectTyposquatPattern() = %q, want empty", result)
			}
		})
	}
}
