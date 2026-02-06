package analyzer

import (
	"context"
	"strings"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestSlopsquattingAnalyzer_Name(t *testing.T) {
	a := NewSlopsquattingAnalyzer()
	if a.Name() != "slopsquatting" {
		t.Errorf("expected name 'slopsquatting', got %q", a.Name())
	}
}

func TestSlopsquattingAnalyzer_LLMPatternNames(t *testing.T) {
	a := NewSlopsquattingAnalyzer()
	ctx := context.Background()

	// Names that look like LLM hallucinations - overly descriptive, using common
	// patterns that ChatGPT/Copilot would suggest
	tests := []struct {
		name     string
		wantFlag bool
	}{
		{"python-flask-validator", true},        // language-framework-utility pattern
		{"node-express-authentication", true},   // triple-compound pattern
		{"react-component-library-utils", true}, // four-word compound
		{"simple-json-parser-helper", true},     // overly generic compound
		{"lodash", false},                       // real popular package
		{"express", false},                      // real popular package
		{"chalk", false},                        // real simple name
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := &registry.PackageMetadata{
				Name: tt.name,
				// No versions = very new package
				Versions: map[string]registry.PackageVersion{
					"1.0.0": {Name: tt.name, Version: "1.0.0"},
				},
			}
			version := &registry.PackageVersion{
				Name:    tt.name,
				Version: "1.0.0",
			}
			findings, err := a.Analyze(ctx, pkg, version)
			if err != nil {
				t.Fatal(err)
			}

			hasFlag := false
			for _, f := range findings {
				if strings.Contains(f.Title, "LLM") || strings.Contains(f.Title, "hallucin") || strings.Contains(f.Title, "slopsquat") {
					hasFlag = true
					break
				}
			}

			if tt.wantFlag && !hasFlag {
				t.Errorf("Expected slopsquatting flag for %q", tt.name)
			}
		})
	}
}

func TestSlopsquattingAnalyzer_OverlyDescriptiveNames(t *testing.T) {
	a := NewSlopsquattingAnalyzer()
	ctx := context.Background()

	pkg := &registry.PackageMetadata{
		Name:     "easy-data-validation-helper-utils",
		Versions: map[string]registry.PackageVersion{"1.0.0": {}},
	}
	version := &registry.PackageVersion{
		Name:    "easy-data-validation-helper-utils",
		Version: "1.0.0",
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Severity >= SeverityMedium {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for overly descriptive package name")
	}
}

func TestSlopsquattingAnalyzer_CommonLLMSuffixes(t *testing.T) {
	a := NewSlopsquattingAnalyzer()
	ctx := context.Background()

	tests := []string{
		"express-helper",
		"react-utils",
		"lodash-toolkit",
		"vue-wrapper",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			pkg := &registry.PackageMetadata{
				Name:     name,
				Versions: map[string]registry.PackageVersion{"1.0.0": {}},
			}
			version := &registry.PackageVersion{
				Name:    name,
				Version: "1.0.0",
			}

			findings, err := a.Analyze(ctx, pkg, version)
			if err != nil {
				t.Fatal(err)
			}

			found := false
			for _, f := range findings {
				if strings.Contains(f.Title, "popular package") || strings.Contains(f.Title, "slopsquat") || strings.Contains(f.Title, "LLM") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected slopsquatting flag for popular-package-suffix name %q", name)
			}
		})
	}
}

func TestSlopsquattingAnalyzer_NormalPackage(t *testing.T) {
	a := NewSlopsquattingAnalyzer()
	ctx := context.Background()

	pkg := &registry.PackageMetadata{
		Name: "chalk",
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {}, "2.0.0": {}, "3.0.0": {}, "4.0.0": {}, "5.0.0": {},
		},
	}
	version := &registry.PackageVersion{Name: "chalk", Version: "5.0.0"}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity for established package: %s", f.Title)
		}
	}
}

func TestIsLLMStyleName(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"python-flask-validator", true},
		{"node-express-authentication", true},
		{"simple-json-parser-helper", true},
		{"react-component-library-utils", true},
		{"chalk", false},
		{"express", false},
		{"is-odd", false},
		{"left-pad", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLLMStyleName(tt.name)
			if result != tt.expected {
				t.Errorf("isLLMStyleName(%q) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}
