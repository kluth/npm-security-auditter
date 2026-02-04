package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Runner orchestrates sandboxed package execution.
type Runner struct {
	nodeAvailable    bool
	unshareAvailable bool
}

// NewRunner creates a sandbox runner. It probes for node, npm, and unshare.
func NewRunner() *Runner {
	r := &Runner{}
	r.nodeAvailable = commandExists("node") && commandExists("npm")
	if runtime.GOOS == "linux" {
		r.unshareAvailable = commandExists("unshare")
	}
	return r
}

// NodeAvailable reports whether node and npm were found in PATH.
func (r *Runner) NodeAvailable() bool {
	return r.nodeAvailable
}

// UnshareAvailable reports whether unshare is available for network isolation.
func (r *Runner) UnshareAvailable() bool {
	return r.unshareAvailable
}

// Run installs a package in a temp directory and runs the harness against it.
// It returns the harness output and whether network isolation was used.
func (r *Runner) Run(ctx context.Context, pkgName, pkgVersion string) (*HarnessOutput, bool, error) {
	if !r.nodeAvailable {
		return nil, false, fmt.Errorf("node and npm are required for sandbox analysis")
	}

	tmpDir, err := os.MkdirTemp("", "auditter-sandbox-*")
	if err != nil {
		return nil, false, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write harness script.
	harnessPath := filepath.Join(tmpDir, "harness.js")
	if err := os.WriteFile(harnessPath, []byte(harnessScript), 0o644); err != nil {
		return nil, false, fmt.Errorf("writing harness: %w", err)
	}

	// npm install with --ignore-scripts.
	installTarget := pkgName
	if pkgVersion != "" {
		installTarget = pkgName + "@" + pkgVersion
	}

	env := sanitizedEnv(tmpDir)

	installCmd := exec.CommandContext(ctx, "npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", installTarget)
	installCmd.Dir = tmpDir
	installCmd.Env = env
	var installStderr bytes.Buffer
	installCmd.Stderr = &installStderr

	if err := installCmd.Run(); err != nil {
		return nil, false, fmt.Errorf("npm install failed: %w: %s", err, installStderr.String())
	}

	// Determine the installed package path.
	pkgPath := filepath.Join(tmpDir, "node_modules", pkgName)

	// Run harness, optionally with network isolation.
	networkIsolated := false
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if r.unshareAvailable {
		cmd := exec.CommandContext(ctx, "unshare", "-rn", "node", harnessPath, pkgPath)
		cmd.Dir = tmpDir
		cmd.Env = env
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			// Fall back to running without unshare.
			stdout.Reset()
			stderr.Reset()
		} else {
			networkIsolated = true
		}
	}

	if !networkIsolated {
		cmd := exec.CommandContext(ctx, "node", harnessPath, pkgPath)
		cmd.Dir = tmpDir
		cmd.Env = env
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			// If the harness itself wrote JSON before failing, try to parse it.
			if stdout.Len() == 0 {
				return nil, false, fmt.Errorf("harness execution failed: %w: %s", err, stderr.String())
			}
		}
	}

	// Parse harness output.
	var output HarnessOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, networkIsolated, fmt.Errorf("parsing harness output: %w (raw: %s)", err, stdout.String())
	}

	return &output, networkIsolated, nil
}

// sanitizedEnv returns a minimal environment for subprocess execution.
func sanitizedEnv(tmpDir string) []string {
	path := os.Getenv("PATH")
	return []string{
		"PATH=" + path,
		"HOME=" + tmpDir,
		"NODE_ENV=production",
		"npm_config_cache=" + filepath.Join(tmpDir, ".npm-cache"),
		"TMPDIR=" + tmpDir,
	}
}

// commandExists checks if a command is available in PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// CheckNodeAvailable is a package-level convenience to check for node+npm.
func CheckNodeAvailable() bool {
	return commandExists("node") && commandExists("npm")
}

// FormatCallArgs formats call record arguments into a human-readable string.
func FormatCallArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.Join(args, ", ")
}
