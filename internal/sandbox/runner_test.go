package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSanitizedEnv(t *testing.T) {
	env := sanitizedEnv("/tmp/test")

	found := make(map[string]bool)
	for _, e := range env {
		parts := splitEnvVar(e)
		if parts[0] != "" {
			found[parts[0]] = true
		}
	}

	required := []string{"PATH", "HOME", "NODE_ENV", "npm_config_cache", "TMPDIR"}
	for _, key := range required {
		if !found[key] {
			t.Errorf("expected %s in sanitized env", key)
		}
	}

	// Ensure sensitive vars are not passed through.
	for _, e := range env {
		parts := splitEnvVar(e)
		if parts[0] == "HOME" && parts[1] != "/tmp/test" {
			t.Errorf("HOME should be set to tmpDir, got %q", parts[1])
		}
	}
}

func splitEnvVar(e string) [2]string {
	for i, c := range e {
		if c == '=' {
			return [2]string{e[:i], e[i+1:]}
		}
	}
	return [2]string{e, ""}
}

func TestCommandExists(t *testing.T) {
	// "ls" or "cmd" should exist on any platform.
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "cmd"
	} else {
		cmd = "ls"
	}

	if !commandExists(cmd) {
		t.Errorf("expected %q to exist", cmd)
	}

	if commandExists("this-command-definitely-does-not-exist-12345") {
		t.Error("expected nonexistent command to return false")
	}
}

func TestCheckNodeAvailable(t *testing.T) {
	// Just ensure it doesn't panic; the result depends on the environment.
	_ = CheckNodeAvailable()
}

func TestFormatCallArgs(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b", "c"}, "a, b, c"},
	}

	for _, tt := range tests {
		got := FormatCallArgs(tt.args)
		if got != tt.want {
			t.Errorf("FormatCallArgs(%v) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestNewRunner(t *testing.T) {
	r := NewRunner()
	if r == nil {
		t.Fatal("NewRunner returned nil")
	}
	// Just check it doesn't panic and reports reasonable values.
	_ = r.NodeAvailable()
	_ = r.UnshareAvailable()
}

func TestIsolationAvailable(t *testing.T) {
	r := NewRunner()
	if runtime.GOOS == "linux" {
		if !r.UnshareAvailable() {
			t.Log("unshare not available on this system")
		}
	}
	if runtime.GOOS == "windows" {
		// We want to ensure Windows Job Object isolation is available/used
		t.Log("Testing Windows isolation")
	}
}

func TestRun_Success(t *testing.T) {
	if !CheckNodeAvailable() {
		t.Fatal("node/npm not available - mandatory for sandbox testing")
	}

	// 1. Setup dummy package
	tmpDir, err := os.MkdirTemp("", "auditter-test-pkg-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pkgJSON := `{"name": "test-pkg", "version": "1.0.0", "main": "index.js"}`
	indexJS := `
const cp = require('child_process');
try {
  cp.execSync('echo hello');
} catch (e) {}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte(indexJS), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Run runner
	r := NewRunner()
	ctx := context.Background()
	// Use file: URL to install from local dir
	output, isolated, err := r.Run(ctx, "test-pkg", "file:"+tmpDir)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	t.Logf("Ran with network isolation: %v", isolated)

	// 3. Verify output
	if !output.Success {
		t.Errorf("expected success, got failure: %v", output.Error)
	}
	if output.InstallPhase.Error != "" {
		t.Errorf("install failed: %v", output.InstallPhase.Error)
	}
	if output.LoadPhase.Error != "" {
		t.Errorf("load failed: %v", output.LoadPhase.Error)
	}

	// Check intercepted calls
	foundExec := false
	for _, call := range output.Intercepted.ChildProcess {
		if call.Method == "execSync" {
			foundExec = true
			break
		}
	}
	if !foundExec {
		t.Errorf("expected execSync to be intercepted, got: %v", output.Intercepted.ChildProcess)
	}
}

func TestRun_InstallFailure(t *testing.T) {
	if !CheckNodeAvailable() {
		t.Fatal("node/npm not available - mandatory for sandbox testing")
	}

	r := NewRunner()
	ctx := context.Background()
	// Non-existent package
	_, _, err := r.Run(ctx, "non-existent-package-12345-xyz", "1.0.0")
	if err == nil {
		t.Error("expected error for non-existent package, got nil")
	}
}

func TestRun_WithoutUnshare(t *testing.T) {
	if !CheckNodeAvailable() {
		t.Fatal("node/npm not available - mandatory for sandbox testing")
	}

	tmpDir, err := os.MkdirTemp("", "auditter-test-pkg-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a simple package
	pkgJSON := `{"name": "test-pkg-nounshare", "version": "1.0.0", "main": "index.js"}`
	indexJS := `// do nothing`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte(indexJS), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewRunner()
	r.unshareAvailable = false // Force disable unshare

	ctx := context.Background()
	_, isolated, err := r.Run(ctx, "test-pkg-nounshare", "file:"+tmpDir)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if isolated {
		t.Error("expected not isolated")
	}
}

func TestRun_HarnessGarbageOutput(t *testing.T) {
	if !CheckNodeAvailable() {
		t.Fatal("node/npm not available - mandatory for sandbox testing")
	}

	tmpDir, err := os.MkdirTemp("", "auditter-test-pkg-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pkgJSON := `{"name": "test-pkg-garbage", "version": "1.0.0", "main": "index.js"}`
	// The harness wraps the execution. We need to make the harness output garbage?
	// The harness script catches errors.
	// But if the process crashes hard (e.g. segfault) or we can't make node crash easily.
	// Wait, Run expects the harness to print JSON at the end.
	// The harness prints JSON even if exception occurs.
	// To make parsing fail, the harness must output non-JSON or nothing.
	// If I put `process.exit(1)` immediately in `index.js`, harness wraps it?
	// The harness runs `require(pkgPath)`.
	// If `process.exit` is called, the harness script stops.
	// So `index.js` doing `process.exit(0)` will prevent harness from printing JSON.

	indexJS := `process.exit(0);`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte(indexJS), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewRunner()
	ctx := context.Background()
	_, _, err = r.Run(ctx, "test-pkg-garbage", "file:"+tmpDir)
	if err == nil {
		t.Error("expected error due to garbage/empty output, got nil")
	}
}

func TestRun_UnshareFail(t *testing.T) {
	if !CheckNodeAvailable() {
		t.Fatal("node/npm not available - mandatory for sandbox testing")
	}

	// 1. Setup fake unshare
	tmpBin, err := os.MkdirTemp("", "fake-bin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpBin)

	fakeUnsharePath := filepath.Join(tmpBin, "unshare")
	// Create a script that fails
	script := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(fakeUnsharePath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	// 2. Manipulate PATH
	oldPath := os.Getenv("PATH")
	defer os.Setenv("PATH", oldPath)
	os.Setenv("PATH", tmpBin+string(os.PathListSeparator)+oldPath)

	// 3. Setup dummy package
	tmpDir, err := os.MkdirTemp("", "auditter-test-pkg-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pkgJSON := `{"name": "test-pkg-unsharefail", "version": "1.0.0", "main": "index.js"}`
	indexJS := `// do nothing`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte(indexJS), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Run
	r := NewRunner()
	// Verify it picked up unshare (our fake one or the real one if something went wrong, 
    // but NewRunner just checks existence)
	if !r.UnshareAvailable() {
		t.Fatal("expected unshare to be available (our fake one)")
	}

	ctx := context.Background()
	_, isolated, err := r.Run(ctx, "test-pkg-unsharefail", "file:"+tmpDir)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if isolated {
		t.Error("expected not isolated (unshare should have failed)")
	}
}
