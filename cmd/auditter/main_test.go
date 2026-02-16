package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/reporter"
	"github.com/spf13/cobra"
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
	if err := os.WriteFile(lockPath, []byte(`{
		"name":"test",
		"lockfileVersion":3,
		"packages":{
			"node_modules/nonexistent-xyz":{"version":"1.0.0"}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

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
	if err := os.WriteFile(pkgPath, []byte(`{"name":"test","dependencies":{"nonexistent-xyz":"^1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

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
		_ = json.NewEncoder(w).Encode(metadata)
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
		_ = json.NewEncoder(w).Encode(metadata)
	}))
	defer srv.Close()

	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	if err := os.WriteFile(pkgPath, []byte(`{"name":"test","dependencies":{"dep-a":"^1.0.0","dep-b":"^2.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

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
		_ = json.NewEncoder(w).Encode(metadata)
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
		_ = json.NewEncoder(w).Encode(metadata)
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

// ─── Feature 1: --quiet flag tests ────────────────────────────────────────

func TestStderrPrintfQuiet(t *testing.T) {
	quiet = true
	defer func() { quiet = false }()

	// stderrPrintf should not panic even when quiet
	stderrPrintf("this should be suppressed: %s\n", "test")
}

func TestStderrPrintfNotQuiet(t *testing.T) {
	quiet = false
	// stderrPrintf should work without error
	stderrPrintf("this should print: %s\n", "test")
}

func TestQuietAndVerboseMutualExclusion(t *testing.T) {
	quiet = true
	verbose = true
	interactive = false
	listAnalyzers = false
	failOn = ""
	defer func() {
		quiet = false
		verbose = false
	}()

	err := run(nil, []string{"test-pkg"})
	if err == nil {
		t.Error("expected error for --quiet and --verbose together")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' error, got: %v", err)
	}
}

func TestQuietSuppressesStderrInAudit(t *testing.T) {
	metadata := registry.PackageMetadata{
		Name:        "test-pkg",
		DistTags:    map[string]string{"latest": "1.0.0"},
		Versions:    map[string]registry.PackageVersion{"1.0.0": {Name: "test-pkg", Version: "1.0.0", License: "MIT"}},
		Maintainers: []registry.Maintainer{{Name: "u", Email: "u@co.com"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
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
	timeout = 30
	concurrency = 1
	quiet = true
	verbose = false
	failOn = ""
	listAnalyzers = false

	defer func() {
		registryURL = ""
		noSandbox = false
		format = "terminal"
		quiet = false
	}()

	err := run(nil, []string{"test-pkg"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestQuietStillOutputsReport(t *testing.T) {
	metadata := registry.PackageMetadata{
		Name:        "test-pkg",
		DistTags:    map[string]string{"latest": "1.0.0"},
		Versions:    map[string]registry.PackageVersion{"1.0.0": {Name: "test-pkg", Version: "1.0.0", License: "MIT"}},
		Maintainers: []registry.Maintainer{{Name: "u", Email: "u@co.com"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	}))
	defer srv.Close()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.json")

	interactive = false
	projectPath = ""
	auditNodeModules = false
	registryURL = srv.URL
	minSeverity = ""
	noSandbox = true
	outputFile = outPath
	format = "json"
	timeout = 30
	concurrency = 1
	quiet = true
	verbose = false
	failOn = ""
	listAnalyzers = false

	defer func() {
		registryURL = ""
		outputFile = ""
		noSandbox = false
		format = "terminal"
		quiet = false
	}()

	err := run(nil, []string{"test-pkg"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty report output even in quiet mode")
	}
}

// ─── Feature 2: --fail-on flag tests ──────────────────────────────────────

func TestCheckFailOnNoFindings(t *testing.T) {
	pr := reporter.ProjectReport{Reports: []reporter.Report{
		{Package: "test", Version: "1.0.0", Results: []analyzer.Result{}},
	}}
	err := checkFailOn(pr, "low")
	if err != nil {
		t.Errorf("expected nil error for no findings, got: %v", err)
	}
}

func TestCheckFailOnBelowThreshold(t *testing.T) {
	pr := reporter.ProjectReport{Reports: []reporter.Report{
		{Package: "test", Version: "1.0.0", Results: []analyzer.Result{
			{AnalyzerName: "test", Findings: []analyzer.Finding{
				{Severity: analyzer.SeverityLow, Title: "minor issue"},
			}},
		}},
	}}
	err := checkFailOn(pr, "high")
	if err != nil {
		t.Errorf("expected nil for findings below threshold, got: %v", err)
	}
}

func TestCheckFailOnMeetsThreshold(t *testing.T) {
	pr := reporter.ProjectReport{Reports: []reporter.Report{
		{Package: "test", Version: "1.0.0", Results: []analyzer.Result{
			{AnalyzerName: "test", Findings: []analyzer.Finding{
				{Severity: analyzer.SeverityHigh, Title: "serious issue"},
			}},
		}},
	}}
	err := checkFailOn(pr, "high")
	if err == nil {
		t.Error("expected ExitError when findings meet threshold")
	}
	exitErr, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError, got %T", err)
	}
	if exitErr.Code != 2 {
		t.Errorf("expected exit code 2, got %d", exitErr.Code)
	}
}

func TestCheckFailOnExceedsThreshold(t *testing.T) {
	pr := reporter.ProjectReport{Reports: []reporter.Report{
		{Package: "test", Version: "1.0.0", Results: []analyzer.Result{
			{AnalyzerName: "test", Findings: []analyzer.Finding{
				{Severity: analyzer.SeverityCritical, Title: "critical issue"},
			}},
		}},
	}}
	err := checkFailOn(pr, "high")
	if err == nil {
		t.Error("expected ExitError when findings exceed threshold")
	}
	exitErr, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError, got %T", err)
	}
	if exitErr.Code != 2 {
		t.Errorf("expected exit code 2, got %d", exitErr.Code)
	}
}

func TestCheckFailOnMultipleReports(t *testing.T) {
	pr := reporter.ProjectReport{Reports: []reporter.Report{
		{Package: "clean", Version: "1.0.0", Results: []analyzer.Result{
			{AnalyzerName: "test", Findings: []analyzer.Finding{
				{Severity: analyzer.SeverityLow, Title: "minor"},
			}},
		}},
		{Package: "dirty", Version: "2.0.0", Results: []analyzer.Result{
			{AnalyzerName: "test", Findings: []analyzer.Finding{
				{Severity: analyzer.SeverityCritical, Title: "bad"},
			}},
		}},
	}}
	err := checkFailOn(pr, "high")
	if err == nil {
		t.Error("expected ExitError when second report has findings above threshold")
	}
}

func TestCheckFailOnEmptyString(t *testing.T) {
	// failOn="" should mean no check (handled in run, not checkFailOn)
	interactive = false
	projectPath = ""
	auditNodeModules = false
	minSeverity = ""
	noSandbox = true
	outputFile = ""
	format = "json"
	timeout = 10
	concurrency = 1
	quiet = false
	verbose = false
	failOn = ""
	listAnalyzers = false

	defer func() {
		noSandbox = false
		format = "terminal"
	}()

	err := run(nil, []string{"nonexistent-package-xyz-12345"})
	// Should not trigger any exit error (just a skipped package)
	if exitErr, ok := err.(*ExitError); ok {
		t.Errorf("unexpected ExitError with empty failOn: %v", exitErr)
	}
}

func TestRunFailOnInvalidSeverity(t *testing.T) {
	interactive = false
	projectPath = ""
	auditNodeModules = false
	failOn = "invalid"
	quiet = false
	verbose = false
	listAnalyzers = false

	defer func() { failOn = "" }()

	err := run(nil, []string{"test-pkg"})
	if err == nil {
		t.Error("expected error for invalid --fail-on value")
	}
}

func TestFailOnIntegrationWithMockRegistry(t *testing.T) {
	metadata := registry.PackageMetadata{
		Name:        "test-pkg",
		DistTags:    map[string]string{"latest": "1.0.0"},
		Versions:    map[string]registry.PackageVersion{"1.0.0": {Name: "test-pkg", Version: "1.0.0", License: "MIT"}},
		Maintainers: []registry.Maintainer{{Name: "u", Email: "u@co.com"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
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
	timeout = 30
	concurrency = 1
	quiet = false
	verbose = false
	failOn = "critical"
	listAnalyzers = false

	defer func() {
		registryURL = ""
		noSandbox = false
		format = "terminal"
		failOn = ""
	}()

	err := run(nil, []string{"test-pkg"})
	// A simple test package with MIT license may or may not trigger critical findings.
	// The test exercises the --fail-on path without asserting the specific outcome
	// since findings depend on the analyzer heuristics.
	_ = err
}

func TestExitErrorInterface(t *testing.T) {
	e := &ExitError{Code: 2, Message: "test message"}
	if e.Error() != "test message" {
		t.Errorf("ExitError.Error() = %q, want %q", e.Error(), "test message")
	}
}

// ─── Feature 3: --list-analyzers flag tests ───────────────────────────────

func TestAnalyzerRegistryCount(t *testing.T) {
	infos := analyzerRegistry()
	if len(infos) != 57 {
		t.Errorf("expected 57 analyzers in registry, got %d", len(infos))
	}
}

func TestAnalyzerRegistryAllFieldsPopulated(t *testing.T) {
	infos := analyzerRegistry()
	for i, info := range infos {
		if info.Name == "" {
			t.Errorf("analyzer %d has empty Name", i)
		}
		if info.Category == "" {
			t.Errorf("analyzer %d (%s) has empty Category", i, info.Name)
		}
		if info.Description == "" {
			t.Errorf("analyzer %d (%s) has empty Description", i, info.Name)
		}
	}
}

func TestAnalyzerRegistryCategories(t *testing.T) {
	validCategories := map[string]bool{
		"Supply Chain":      true,
		"Code Analysis":     true,
		"Malware Detection": true,
		"Build Integrity":   true,
		"Runtime Analysis":  true,
	}

	infos := analyzerRegistry()
	for _, info := range infos {
		if !validCategories[info.Category] {
			t.Errorf("analyzer %q has invalid category %q", info.Name, info.Category)
		}
	}
}

func TestPrintAnalyzerListOutput(t *testing.T) {
	var buf bytes.Buffer
	printAnalyzerList(&buf)
	output := buf.String()

	if !strings.Contains(output, "ANALYZER") {
		t.Error("output should contain header 'ANALYZER'")
	}
	if !strings.Contains(output, "CATEGORY") {
		t.Error("output should contain header 'CATEGORY'")
	}
	if !strings.Contains(output, "DESCRIPTION") {
		t.Error("output should contain header 'DESCRIPTION'")
	}
	if !strings.Contains(output, "Total: 57 analyzers") {
		t.Errorf("output should contain 'Total: 57 analyzers', got: %s", output[strings.LastIndex(output, "Total"):])
	}
	if !strings.Contains(output, "vulnerabilities") {
		t.Error("output should contain 'vulnerabilities' analyzer")
	}
}

func TestListAnalyzersExitsEarly(t *testing.T) {
	listAnalyzers = true
	quiet = false
	verbose = false
	failOn = ""
	interactive = false

	defer func() { listAnalyzers = false }()

	// Should succeed even without args
	err := run(nil, nil)
	if err != nil {
		t.Errorf("expected nil error with --list-analyzers, got: %v", err)
	}
}

func TestAnalyzerRegistryUniqueNames(t *testing.T) {
	infos := analyzerRegistry()
	seen := make(map[string]bool)
	for _, info := range infos {
		if seen[info.Name] {
			t.Errorf("duplicate analyzer name: %s", info.Name)
		}
		seen[info.Name] = true
	}
}

// ─── Feature 4: Environment variable support tests ────────────────────────

func TestResolveStringEnvOverridesDefault(t *testing.T) {
	t.Setenv("AUDITTER_FORMAT", "markdown")
	target := "terminal"
	resolveStringEnv(nil, "format", "AUDITTER_FORMAT", &target)
	if target != "markdown" {
		t.Errorf("expected 'markdown', got %q", target)
	}
}

func TestResolveStringEnvEmptyIgnored(t *testing.T) {
	t.Setenv("AUDITTER_FORMAT", "")
	target := "terminal"
	resolveStringEnv(nil, "format", "AUDITTER_FORMAT", &target)
	if target != "terminal" {
		t.Errorf("expected 'terminal' (unchanged), got %q", target)
	}
}

func TestResolveIntEnvOverridesDefault(t *testing.T) {
	t.Setenv("AUDITTER_TIMEOUT", "300")
	target := 180
	resolveIntEnv(nil, "timeout", "AUDITTER_TIMEOUT", &target)
	if target != 300 {
		t.Errorf("expected 300, got %d", target)
	}
}

func TestResolveIntEnvInvalidIgnored(t *testing.T) {
	t.Setenv("AUDITTER_TIMEOUT", "abc")
	target := 180
	resolveIntEnv(nil, "timeout", "AUDITTER_TIMEOUT", &target)
	if target != 180 {
		t.Errorf("expected 180 (unchanged), got %d", target)
	}
}

func TestResolveBoolEnvOverridesDefault(t *testing.T) {
	t.Setenv("AUDITTER_QUIET", "true")
	target := false
	resolveBoolEnv(nil, "quiet", "AUDITTER_QUIET", &target)
	if !target {
		t.Error("expected true, got false")
	}
}

func TestResolveBoolEnvInvalidIgnored(t *testing.T) {
	t.Setenv("AUDITTER_QUIET", "maybe")
	target := false
	resolveBoolEnv(nil, "quiet", "AUDITTER_QUIET", &target)
	if target {
		t.Error("expected false (unchanged), got true")
	}
}

func TestResolveConfigStringMappings(t *testing.T) {
	envMappings := []struct {
		envKey   string
		envValue string
		target   *string
		flagName string
	}{
		{"AUDITTER_REGISTRY", "http://custom:4873", &registryURL, "registry"},
		{"AUDITTER_FORMAT", "html", &format, "format"},
		{"AUDITTER_LANG", "de", &lang, "lang"},
		{"AUDITTER_SEVERITY", "high", &minSeverity, "severity"},
		{"AUDITTER_FAIL_ON", "critical", &failOn, "fail-on"},
	}

	for _, m := range envMappings {
		t.Run(m.envKey, func(t *testing.T) {
			old := *m.target
			t.Setenv(m.envKey, m.envValue)
			resolveStringEnv(nil, m.flagName, m.envKey, m.target)
			if *m.target != m.envValue {
				t.Errorf("expected %q, got %q", m.envValue, *m.target)
			}
			*m.target = old
		})
	}
}

func TestResolveConfigIntMappings(t *testing.T) {
	t.Setenv("AUDITTER_TIMEOUT", "60")
	t.Setenv("AUDITTER_CONCURRENCY", "10")

	oldTimeout := timeout
	oldConcurrency := concurrency
	defer func() {
		timeout = oldTimeout
		concurrency = oldConcurrency
	}()

	resolveIntEnv(nil, "timeout", "AUDITTER_TIMEOUT", &timeout)
	resolveIntEnv(nil, "concurrency", "AUDITTER_CONCURRENCY", &concurrency)

	if timeout != 60 {
		t.Errorf("expected timeout=60, got %d", timeout)
	}
	if concurrency != 10 {
		t.Errorf("expected concurrency=10, got %d", concurrency)
	}
}

func TestResolveConfigBoolMappings(t *testing.T) {
	t.Setenv("AUDITTER_NO_SANDBOX", "1")
	t.Setenv("AUDITTER_QUIET", "true")

	oldSandbox := noSandbox
	oldQuiet := quiet
	defer func() {
		noSandbox = oldSandbox
		quiet = oldQuiet
	}()

	resolveBoolEnv(nil, "no-sandbox", "AUDITTER_NO_SANDBOX", &noSandbox)
	resolveBoolEnv(nil, "quiet", "AUDITTER_QUIET", &quiet)

	if !noSandbox {
		t.Error("expected noSandbox=true")
	}
	if !quiet {
		t.Error("expected quiet=true")
	}
}

func TestFlagOverridesEnv(t *testing.T) {
	t.Setenv("AUDITTER_FORMAT", "html")

	// Create a minimal cobra command with the format flag
	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&format, "format", "terminal", "")
	// Simulate user passing --format json
	cmd.Flags().Set("format", "json")

	resolveStringEnv(cmd, "format", "AUDITTER_FORMAT", &format)

	if format != "json" {
		t.Errorf("expected flag value 'json' to override env, got %q", format)
	}

	format = "terminal" // restore
}

func TestResolveConfigIntegration(t *testing.T) {
	t.Setenv("AUDITTER_FORMAT", "markdown")
	t.Setenv("AUDITTER_LANG", "de")
	t.Setenv("AUDITTER_TIMEOUT", "60")

	oldFormat := format
	oldLang := lang
	oldTimeout := timeout
	defer func() {
		format = oldFormat
		lang = oldLang
		timeout = oldTimeout
	}()

	resolveConfig(nil)

	if format != "markdown" {
		t.Errorf("expected format=markdown from env, got %q", format)
	}
	if lang != "de" {
		t.Errorf("expected lang=de from env, got %q", lang)
	}
	if timeout != 60 {
		t.Errorf("expected timeout=60 from env, got %d", timeout)
	}
}

func TestFlagChangedNilCmd(t *testing.T) {
	if flagChanged(nil, "format") {
		t.Error("flagChanged should return false for nil cmd")
	}
}

// ─── Feature 5: Config file support tests ─────────────────────────────────

func TestLoadConfigFileValid(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".auditter.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
format: markdown
lang: de
timeout: 60
concurrency: 10
no-sandbox: true
quiet: true
severity: high
fail-on: critical
registry: http://custom:4873
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Format != "markdown" {
		t.Errorf("expected format=markdown, got %q", cfg.Format)
	}
	if cfg.Lang != "de" {
		t.Errorf("expected lang=de, got %q", cfg.Lang)
	}
	if cfg.Timeout != 60 {
		t.Errorf("expected timeout=60, got %d", cfg.Timeout)
	}
	if cfg.Concurrency != 10 {
		t.Errorf("expected concurrency=10, got %d", cfg.Concurrency)
	}
	if !cfg.NoSandbox {
		t.Error("expected no-sandbox=true")
	}
	if !cfg.Quiet {
		t.Error("expected quiet=true")
	}
	if cfg.Severity != "high" {
		t.Errorf("expected severity=high, got %q", cfg.Severity)
	}
	if cfg.FailOn != "critical" {
		t.Errorf("expected fail-on=critical, got %q", cfg.FailOn)
	}
	if cfg.Registry != "http://custom:4873" {
		t.Errorf("expected registry=http://custom:4873, got %q", cfg.Registry)
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	cfg, err := loadConfigFile("/nonexistent/path/.auditter.yaml")
	if err != nil {
		t.Errorf("expected nil error for not found, got: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config for not found")
	}
}

func TestLoadConfigFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".auditter.yaml")
	if err := os.WriteFile(cfgPath, []byte(`{{{invalid yaml`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := loadConfigFile(cfgPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "invalid config file") {
		t.Errorf("expected 'invalid config file' error, got: %v", err)
	}
}

func TestFindConfigFileLocalFirst(t *testing.T) {
	// Create .auditter.yaml in current directory
	if err := os.WriteFile(".auditter.yaml", []byte("format: json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(".auditter.yaml")

	path := findConfigFile()
	if path != ".auditter.yaml" {
		t.Errorf("expected .auditter.yaml, got %q", path)
	}
}

func TestFindConfigFileNone(t *testing.T) {
	// Ensure no local config
	os.Remove(".auditter.yaml")

	path := findConfigFile()
	// path may be "" or a home config path - just verify it doesn't panic
	_ = path
}

func TestApplyConfigAllFields(t *testing.T) {
	oldReg := registryURL
	oldFmt := format
	oldLang := lang
	oldSev := minSeverity
	oldFailOn := failOn
	oldTimeout := timeout
	oldConc := concurrency
	oldSandbox := noSandbox
	oldQuiet := quiet
	defer func() {
		registryURL = oldReg
		format = oldFmt
		lang = oldLang
		minSeverity = oldSev
		failOn = oldFailOn
		timeout = oldTimeout
		concurrency = oldConc
		noSandbox = oldSandbox
		quiet = oldQuiet
	}()

	cfg := &configFile{
		Registry:    "http://local:4873",
		Format:      "csv",
		Lang:        "fr",
		Severity:    "medium",
		FailOn:      "high",
		Timeout:     45,
		Concurrency: 3,
		NoSandbox:   true,
		Quiet:       true,
	}
	applyConfig(cfg)

	if registryURL != "http://local:4873" {
		t.Errorf("expected registry=http://local:4873, got %q", registryURL)
	}
	if format != "csv" {
		t.Errorf("expected format=csv, got %q", format)
	}
	if lang != "fr" {
		t.Errorf("expected lang=fr, got %q", lang)
	}
	if minSeverity != "medium" {
		t.Errorf("expected severity=medium, got %q", minSeverity)
	}
	if failOn != "high" {
		t.Errorf("expected fail-on=high, got %q", failOn)
	}
	if timeout != 45 {
		t.Errorf("expected timeout=45, got %d", timeout)
	}
	if concurrency != 3 {
		t.Errorf("expected concurrency=3, got %d", concurrency)
	}
	if !noSandbox {
		t.Error("expected no-sandbox=true")
	}
	if !quiet {
		t.Error("expected quiet=true")
	}
}

func TestApplyConfigNil(t *testing.T) {
	// Should not panic
	applyConfig(nil)
}

func TestApplyConfigPartial(t *testing.T) {
	oldFmt := format
	oldTimeout := timeout
	defer func() {
		format = oldFmt
		timeout = oldTimeout
	}()

	format = "terminal"
	timeout = 180

	cfg := &configFile{Format: "html"}
	applyConfig(cfg)

	if format != "html" {
		t.Errorf("expected format=html, got %q", format)
	}
	if timeout != 180 {
		t.Errorf("expected timeout=180 (unchanged), got %d", timeout)
	}
}

func TestFullPriorityChain(t *testing.T) {
	// Priority: flag > env > config > default
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".auditter.yaml")
	if err := os.WriteFile(cfgPath, []byte("format: csv\nlang: es\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	oldFmt := format
	oldLang := lang
	defer func() {
		format = oldFmt
		lang = oldLang
	}()

	// Start with defaults
	format = "terminal"
	lang = "en"

	// Apply config (config > default)
	applyConfig(cfg)
	if format != "csv" {
		t.Errorf("after config: expected format=csv, got %q", format)
	}
	if lang != "es" {
		t.Errorf("after config: expected lang=es, got %q", lang)
	}

	// Apply env (env > config)
	t.Setenv("AUDITTER_FORMAT", "html")
	resolveStringEnv(nil, "format", "AUDITTER_FORMAT", &format)
	if format != "html" {
		t.Errorf("after env: expected format=html, got %q", format)
	}
	// lang should stay at config value since no env var set
	if lang != "es" {
		t.Errorf("after env: expected lang=es (unchanged), got %q", lang)
	}

	// Apply flag (flag > env)
	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&format, "format", "terminal", "")
	cmd.Flags().Set("format", "json")
	resolveStringEnv(cmd, "format", "AUDITTER_FORMAT", &format)
	if format != "json" {
		t.Errorf("after flag: expected format=json, got %q", format)
	}
}
