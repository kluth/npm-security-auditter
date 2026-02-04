package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input   string
		want    analyzer.Severity
		wantErr bool
	}{
		{"low", analyzer.SeverityLow, false},
		{"medium", analyzer.SeverityMedium, false},
		{"high", analyzer.SeverityHigh, false},
		{"critical", analyzer.SeverityCritical, false},
		{"invalid", 0, true},
		{"", 0, true},
		{"LOW", 0, true}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSeverity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSeverity(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHasInstallScripts(t *testing.T) {
	tests := []struct {
		name    string
		version *registry.PackageVersion
		want    bool
	}{
		{
			name:    "no scripts",
			version: &registry.PackageVersion{},
			want:    false,
		},
		{
			name: "has HasInstallScript flag",
			version: &registry.PackageVersion{
				HasInstallScript: true,
			},
			want: true,
		},
		{
			name: "has preinstall script",
			version: &registry.PackageVersion{
				Scripts: map[string]string{"preinstall": "echo hello"},
			},
			want: true,
		},
		{
			name: "has install script",
			version: &registry.PackageVersion{
				Scripts: map[string]string{"install": "node-gyp rebuild"},
			},
			want: true,
		},
		{
			name: "has postinstall script",
			version: &registry.PackageVersion{
				Scripts: map[string]string{"postinstall": "node setup.js"},
			},
			want: true,
		},
		{
			name: "only non-install scripts",
			version: &registry.PackageVersion{
				Scripts: map[string]string{"test": "jest", "build": "tsc"},
			},
			want: false,
		},
		{
			name:    "nil scripts map",
			version: &registry.PackageVersion{Scripts: nil},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasInstallScripts(tt.version)
			if got != tt.want {
				t.Errorf("hasInstallScripts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunNoArgs(t *testing.T) {
	// Test that run() returns an error when no args, no project, and not interactive
	interactive = false
	projectPath = ""
	auditNodeModules = false

	err := run(nil, nil)
	if err == nil {
		t.Error("expected error when no args provided")
	}
}

func TestRunInvalidProjectPath(t *testing.T) {
	interactive = false
	projectPath = "somefile.txt"
	auditNodeModules = false

	err := run(nil, nil)
	if err == nil {
		t.Error("expected error for invalid project path")
	}
}

func TestRunPackageJsonNotFound(t *testing.T) {
	interactive = false
	projectPath = "/nonexistent/package.json"
	auditNodeModules = false

	err := run(nil, nil)
	if err == nil {
		t.Error("expected error for missing package.json")
	}
}

func TestRunPackageLockNotFound(t *testing.T) {
	interactive = false
	projectPath = "/nonexistent/package-lock.json"
	auditNodeModules = false

	err := run(nil, nil)
	if err == nil {
		t.Error("expected error for missing package-lock.json")
	}
}

func TestRunNodeModulesNotFound(t *testing.T) {
	interactive = false
	projectPath = ""
	auditNodeModules = true

	// Restore
	defer func() { auditNodeModules = false }()

	err := run(nil, []string{})
	if err == nil {
		t.Error("expected error when node_modules doesn't exist")
	}
}

func TestRunInvalidSeverity(t *testing.T) {
	interactive = false
	projectPath = ""
	auditNodeModules = false
	minSeverity = "invalid"

	defer func() { minSeverity = "" }()

	err := run(nil, []string{"test-pkg"})
	if err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestRunWithJsonFlag(t *testing.T) {
	interactive = false
	projectPath = ""
	auditNodeModules = false
	jsonOutput = true
	minSeverity = ""
	noSandbox = true
	outputFile = ""
	format = "terminal"
	timeout = 10
	concurrency = 1

	defer func() {
		jsonOutput = false
		noSandbox = false
	}()

	// This will fail because the package doesn't exist on the real registry,
	// but it exercises the jsonOutput -> format="json" path and the audit path
	err := run(nil, []string{"nonexistent-package-xyz-12345"})
	// No error because registry errors are silently skipped (non-verbose)
	_ = err
}

func TestRunWithOutputFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.json")

	interactive = false
	projectPath = ""
	auditNodeModules = false
	jsonOutput = false
	format = "json"
	minSeverity = ""
	noSandbox = true
	outputFile = outPath
	timeout = 10
	concurrency = 1

	defer func() {
		outputFile = ""
		noSandbox = false
		format = "terminal"
	}()

	err := run(nil, []string{"nonexistent-package-xyz-12345"})
	_ = err

	// Verify file was created
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("expected output file to be created")
	}
}

func TestRunWithSeverityFilter(t *testing.T) {
	interactive = false
	projectPath = ""
	auditNodeModules = false
	minSeverity = "high"
	noSandbox = true
	outputFile = ""
	format = "terminal"
	timeout = 10
	concurrency = 1

	defer func() {
		minSeverity = ""
		noSandbox = false
	}()

	err := run(nil, []string{"nonexistent-package-xyz-12345"})
	_ = err
}

func TestRunWithPackageLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "package-lock.json")
	os.WriteFile(lockPath, []byte(`{
		"name":"test",
		"lockfileVersion":3,
		"packages":{
			"node_modules/nonexistent-xyz":{"version":"1.0.0"}
		}
	}`), 0o644)

	interactive = false
	projectPath = lockPath
	auditNodeModules = false
	minSeverity = ""
	noSandbox = true
	outputFile = ""
	format = "json"
	timeout = 10
	concurrency = 1

	defer func() {
		projectPath = ""
		noSandbox = false
		format = "terminal"
	}()

	err := run(nil, nil)
	_ = err
}

func TestRunConcurrencyClamp(t *testing.T) {
	interactive = false
	projectPath = ""
	auditNodeModules = false
	minSeverity = ""
	noSandbox = true
	outputFile = ""
	format = "json"
	timeout = 10
	concurrency = 0 // should be clamped to 1

	defer func() {
		concurrency = 5
		noSandbox = false
		format = "terminal"
	}()

	err := run(nil, []string{"nonexistent-xyz-12345"})
	_ = err
}

func TestRunWithValidPackageJSON(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	os.WriteFile(pkgPath, []byte(`{"name":"test","dependencies":{"nonexistent-xyz":"^1.0.0"}}`), 0o644)

	interactive = false
	projectPath = pkgPath
	auditNodeModules = false
	minSeverity = ""
	noSandbox = true
	outputFile = ""
	format = "json"
	timeout = 10
	concurrency = 1

	defer func() {
		projectPath = ""
		noSandbox = false
		format = "terminal"
	}()

	err := run(nil, nil)
	// Should not error - registry failures are silently skipped
	_ = err
}

func TestRunWithMockRegistry(t *testing.T) {
	// Set up mock registry server
	metadata := registry.PackageMetadata{
		Name:        "test-pkg",
		Description: "A test package",
		DistTags:    map[string]string{"latest": "1.0.0"},
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {
				Name:    "test-pkg",
				Version: "1.0.0",
				License: "MIT",
				Scripts: map[string]string{"test": "jest"},
			},
		},
		Maintainers: []registry.Maintainer{{Name: "user", Email: "user@example.com"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer srv.Close()

	interactive = false
	projectPath = ""
	auditNodeModules = false
	registryURL = srv.URL
	minSeverity = "high"
	noSandbox = true
	outputFile = ""
	format = "json"
	timeout = 30
	concurrency = 1
	verbose = true

	defer func() {
		registryURL = ""
		minSeverity = ""
		noSandbox = false
		format = "terminal"
		verbose = false
	}()

	err := run(nil, []string{"test-pkg"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunWithMockRegistryProjectMode(t *testing.T) {
	metadata := registry.PackageMetadata{
		Name:     "dep-a",
		DistTags: map[string]string{"latest": "1.0.0"},
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {
				Name:    "dep-a",
				Version: "1.0.0",
				License: "MIT",
			},
		},
		Maintainers: []registry.Maintainer{{Name: "u", Email: "u@co.com"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer srv.Close()

	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	os.WriteFile(pkgPath, []byte(`{"name":"test","dependencies":{"dep-a":"^1.0.0","dep-b":"^2.0.0"}}`), 0o644)

	interactive = false
	projectPath = pkgPath
	auditNodeModules = false
	registryURL = srv.URL
	minSeverity = ""
	noSandbox = true
	outputFile = ""
	format = "terminal"
	timeout = 30
	concurrency = 2
	verbose = false

	defer func() {
		projectPath = ""
		registryURL = ""
		noSandbox = false
	}()

	err := run(nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunOutputFileCreationError(t *testing.T) {
	interactive = false
	projectPath = ""
	auditNodeModules = false
	minSeverity = ""
	noSandbox = true
	outputFile = "/nonexistent-dir-xyz/report.json"
	format = "json"
	timeout = 10
	concurrency = 1

	defer func() {
		outputFile = ""
		noSandbox = false
		format = "terminal"
	}()

	err := run(nil, []string{"test-pkg"})
	if err == nil {
		t.Error("expected error for unwritable output file")
	}
}

func TestRunVerboseNoLatest(t *testing.T) {
	// Registry returns a package with no "latest" tag
	metadata := registry.PackageMetadata{
		Name:     "test-pkg",
		DistTags: map[string]string{}, // no latest
		Versions: map[string]registry.PackageVersion{},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer srv.Close()

	interactive = false
	projectPath = ""
	auditNodeModules = false
	registryURL = srv.URL
	minSeverity = ""
	noSandbox = true
	outputFile = ""
	format = "json"
	timeout = 10
	concurrency = 1
	verbose = true

	defer func() {
		registryURL = ""
		noSandbox = false
		format = "terminal"
		verbose = false
	}()

	err := run(nil, []string{"test-pkg"})
	// Should succeed but skip the package (no latest tag)
	_ = err
}

func TestRunVerboseVersionNotFound(t *testing.T) {
	// Registry returns a package where the latest version doesn't exist in Versions map
	metadata := registry.PackageMetadata{
		Name:     "test-pkg",
		DistTags: map[string]string{"latest": "2.0.0"},
		Versions: map[string]registry.PackageVersion{
			"1.0.0": {Name: "test-pkg", Version: "1.0.0"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer srv.Close()

	interactive = false
	projectPath = ""
	auditNodeModules = false
	registryURL = srv.URL
	minSeverity = ""
	noSandbox = true
	outputFile = ""
	format = "json"
	timeout = 10
	concurrency = 1
	verbose = true

	defer func() {
		registryURL = ""
		noSandbox = false
		format = "terminal"
		verbose = false
	}()

	err := run(nil, []string{"test-pkg"})
	_ = err
}
