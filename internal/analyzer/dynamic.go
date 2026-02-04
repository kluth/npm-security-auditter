package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/matthias/auditter/internal/registry"
	"github.com/matthias/auditter/internal/sandbox"
)

// SandboxAnalyzer performs dynamic analysis by running the package in a sandbox.
type SandboxAnalyzer struct {
	runner *sandbox.Runner
}

func NewSandboxAnalyzer() *SandboxAnalyzer {
	return &SandboxAnalyzer{
		runner: sandbox.NewRunner(),
	}
}

func (a *SandboxAnalyzer) Name() string {
	return "dynamic-analysis"
}

func (a *SandboxAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	if !a.runner.NodeAvailable() {
		return nil, fmt.Errorf("node and npm are required for dynamic analysis but were not found in PATH")
	}

	output, networkIsolated, err := a.runner.Run(ctx, pkg.Name, version.Version)
	if err != nil {
		return nil, fmt.Errorf("sandbox execution failed: %w", err)
	}

	var findings []Finding

	if !networkIsolated && a.runner.UnshareAvailable() {
		// This shouldn't normally happen, but just in case.
	} else if !networkIsolated {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Sandbox ran without network isolation",
			Description: "The sandbox executed without network namespace isolation (unshare not available). Network calls were blocked at the application level only.",
			Severity:    SeverityLow,
		})
	}

	// Check for timeout.
	if output.Error != "" && strings.Contains(output.Error, "timeout") {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Package loading timed out",
			Description: fmt.Sprintf("The package did not finish loading within the sandbox timeout: %s. This may indicate an infinite loop or hanging network request.", output.Error),
			Severity:    SeverityMedium,
		})
	}

	// child_process calls -> CRITICAL
	for _, call := range output.Intercepted.ChildProcess {
		findings = append(findings, Finding{
			Analyzer:       a.Name(),
			Title:          "Process execution attempt",
			Description:    fmt.Sprintf("The package attempted to execute a process via %s(%s).", call.Method, sandbox.FormatCallArgs(call.Args)),
			Severity:       SeverityCritical,
			ExploitExample: fmt.Sprintf("Intercepted call: %s(%s)\nStack trace:\n%s", call.Method, sandbox.FormatCallArgs(call.Args), call.Stack),
		})
	}

	// Network calls -> HIGH
	for _, call := range output.Intercepted.Network {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Network connection attempt",
			Description: fmt.Sprintf("The package attempted a network connection via %s(%s).", call.Method, sandbox.FormatCallArgs(call.Args)),
			Severity:    SeverityHigh,
		})
	}

	// DNS lookups -> HIGH
	for _, call := range output.Intercepted.DNS {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "DNS lookup attempt",
			Description: fmt.Sprintf("The package attempted a DNS lookup via %s(%s).", call.Method, sandbox.FormatCallArgs(call.Args)),
			Severity:    SeverityHigh,
		})
	}

	// File system access -> check for sensitive paths.
	sensitivePathPrefixes := []string{".ssh", ".npmrc", ".env", ".aws", ".docker", ".kube", "/etc/passwd", "/etc/shadow"}
	for _, call := range output.Intercepted.FileSystem {
		isSensitive := false
		for _, arg := range call.Args {
			for _, prefix := range sensitivePathPrefixes {
				if strings.Contains(arg, prefix) {
					isSensitive = true
					break
				}
			}
			if isSensitive {
				break
			}
		}

		if isSensitive {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Sensitive file access attempt",
				Description: fmt.Sprintf("The package attempted to access a sensitive file via %s(%s).", call.Method, sandbox.FormatCallArgs(call.Args)),
				Severity:    SeverityCritical,
			})
		}
	}

	// process.env access -> MEDIUM
	if len(output.Intercepted.ProcessEnv) > 0 {
		accessedKeys := make(map[string]bool)
		for _, call := range output.Intercepted.ProcessEnv {
			if call.Method == "get" && len(call.Args) > 0 {
				key := call.Args[0]
				// Skip common/benign env vars.
				if key == "NODE_ENV" || key == "PATH" || key == "HOME" {
					continue
				}
				accessedKeys[key] = true
			}
		}

		if len(accessedKeys) > 0 {
			keys := make([]string, 0, len(accessedKeys))
			for k := range accessedKeys {
				keys = append(keys, k)
			}
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Environment variable access",
				Description: fmt.Sprintf("The package accessed %d environment variables: %s", len(keys), strings.Join(keys, ", ")),
				Severity:    SeverityMedium,
			})
		}
	}

	return findings, nil
}
