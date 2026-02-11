package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/sandbox"
)

// SandboxAnalyzer performs dynamic analysis by running the package in a sandbox.
// It intercepts and monitors calls to 15+ Node.js core modules including:
// child_process, fs, net/http/https, dns, crypto, vm, worker_threads, cluster, etc.
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
	findings = append(findings, a.checkIsolation(networkIsolated, output)...)
	findings = append(findings, a.checkInterceptedCalls(output)...)
	findings = append(findings, a.checkSensitiveFileAccess(output)...)
	findings = append(findings, a.checkEnvAccess(output)...)

	return findings, nil
}

func (a *SandboxAnalyzer) checkIsolation(networkIsolated bool, output *sandbox.HarnessOutput) []Finding {
	var findings []Finding

	if !networkIsolated && a.runner.UnshareAvailable() {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "sandbox_isolation_degraded",
			Description: "sandbox_isolation_degraded_desc", Severity: SeverityMedium,
		})
	} else if !networkIsolated {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "sandbox_no_isolation",
			Description: "sandbox_no_isolation_desc", Severity: SeverityLow,
		})
	}

	if len(output.PatchErrors) > 0 {
		modules := make([]string, len(output.PatchErrors))
		for i, pe := range output.PatchErrors {
			modules[i] = pe.Module
		}
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "sandbox_patch_errors",
			Description: fmt.Sprintf("Failed to patch modules: %s. Some behaviors may not have been intercepted.", strings.Join(modules, ", ")),
			Severity:    SeverityLow,
		})
	}

	if output.Error != "" && strings.Contains(output.Error, "timeout") {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_timeout",
			Description:    fmt.Sprintf("dynamic_timeout_desc: %s", output.Error),
			Severity:       SeverityMedium,
			ExploitExample: "dynamic_timeout_exploit",
			Remediation:    "dynamic_timeout_remediation",
		})
	}

	return findings
}

func (a *SandboxAnalyzer) checkInterceptedCalls(output *sandbox.HarnessOutput) []Finding {
	var findings []Finding

	for _, call := range output.Intercepted.Eval {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_eval_detected",
			Description:    fmt.Sprintf("The package used %s() which can execute arbitrary code.", call.Method),
			Severity:       SeverityCritical,
			ExploitExample: fmt.Sprintf("Intercepted: %s(%s)\n\nStack trace:\n%s", call.Method, truncateArgs(call.Args), call.Stack),
			Remediation:    "dynamic_eval_remediation",
		})
	}

	for _, call := range output.Intercepted.ChildProcess {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_process_exec",
			Description:    fmt.Sprintf("The package attempted to execute a process via %s(%s).", call.Method, sandbox.FormatCallArgs(call.Args)),
			Severity:       SeverityCritical,
			ExploitExample: fmt.Sprintf("Intercepted: %s(%s)\n\nStack trace:\n%s", call.Method, sandbox.FormatCallArgs(call.Args), call.Stack),
			Remediation:    "dynamic_process_remediation",
		})
	}

	for _, call := range output.Intercepted.Worker {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_worker_threads",
			Description:    fmt.Sprintf("The package attempted to spawn a worker thread via %s.", call.Method),
			Severity:       SeverityCritical,
			ExploitExample: "dynamic_worker_exploit",
			Remediation:    "dynamic_worker_remediation",
		})
	}

	for _, call := range output.Intercepted.Cluster {
		if call.Method == "fork" {
			findings = append(findings, Finding{
				Analyzer: a.Name(), Title: "dynamic_cluster_fork",
				Description: "The package attempted to fork a cluster worker process.",
				Severity:    SeverityCritical, ExploitExample: "dynamic_cluster_exploit",
				Remediation: "dynamic_cluster_remediation",
			})
		}
	}

	findings = append(findings, a.checkNetworkCalls(output)...)

	for _, call := range output.Intercepted.Dgram {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_udp_socket",
			Description:    fmt.Sprintf("The package attempted to create a UDP socket via %s.", call.Method),
			Severity:       SeverityHigh,
			ExploitExample: "dynamic_udp_exploit",
			Remediation:    "dynamic_udp_remediation",
		})
	}

	for _, call := range output.Intercepted.TLS {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_tls_connection",
			Description: fmt.Sprintf("The package attempted a TLS connection via %s(%s).", call.Method, sandbox.FormatCallArgs(call.Args)),
			Severity:    SeverityHigh,
		})
	}

	for _, call := range output.Intercepted.VM {
		sev := SeverityMedium
		if strings.Contains(call.Method, "NewContext") || call.Method == "compileFunction" {
			sev = SeverityHigh
		}
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_vm_usage",
			Description:    fmt.Sprintf("The package used vm.%s() which can execute code in isolated contexts.", call.Method),
			Severity:       sev,
			ExploitExample: "dynamic_vm_exploit",
			Remediation:    "dynamic_vm_remediation",
		})
	}

	return findings
}

func (a *SandboxAnalyzer) checkNetworkCalls(output *sandbox.HarnessOutput) []Finding {
	var findings []Finding

	networkTargets := make(map[string]bool)
	for _, call := range output.Intercepted.Network {
		target := "unknown"
		if len(call.Args) > 0 {
			target = call.Args[0]
		}
		if !networkTargets[target] {
			networkTargets[target] = true
			findings = append(findings, Finding{
				Analyzer: a.Name(), Title: "dynamic_network_request",
				Description:    fmt.Sprintf("The package attempted a network connection via %s to: %s", call.Method, target),
				Severity:       SeverityHigh,
				ExploitExample: fmt.Sprintf("Intercepted: %s(%s)", call.Method, sandbox.FormatCallArgs(call.Args)),
				Remediation:    "dynamic_network_remediation",
			})
		}
	}

	dnsTargets := make(map[string]bool)
	for _, call := range output.Intercepted.DNS {
		target := "unknown"
		if len(call.Args) > 0 {
			target = call.Args[0]
		}
		if !dnsTargets[target] {
			dnsTargets[target] = true
			findings = append(findings, Finding{
				Analyzer: a.Name(), Title: "dynamic_dns_lookup",
				Description:    fmt.Sprintf("The package attempted a DNS lookup via %s for: %s", call.Method, target),
				Severity:       SeverityHigh,
				ExploitExample: "dynamic_dns_exploit",
				Remediation:    "dynamic_dns_remediation",
			})
		}
	}

	return findings
}

var sensitivePathPrefixes = []string{
	".ssh", ".npmrc", ".env", ".aws", ".docker", ".kube",
	"/etc/passwd", "/etc/shadow", "/etc/hosts",
	".gitconfig", ".git/config", ".netrc", ".pgpass",
	".bash_history", ".zsh_history", ".node_repl_history",
	"id_rsa", "id_ed25519", "known_hosts",
}

func (a *SandboxAnalyzer) checkSensitiveFileAccess(output *sandbox.HarnessOutput) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, call := range output.Intercepted.FileSystem {
		for _, arg := range call.Args {
			for _, prefix := range sensitivePathPrefixes {
				if strings.Contains(arg, prefix) && !seen[arg] {
					seen[arg] = true
					findings = append(findings, Finding{
						Analyzer: a.Name(), Title: "dynamic_sensitive_file",
						Description:    fmt.Sprintf("The package attempted to access a sensitive file: %s via %s.", arg, call.Method),
						Severity:       SeverityCritical,
						ExploitExample: "dynamic_sensitive_file_exploit",
						Remediation:    "dynamic_sensitive_file_remediation",
					})
					break
				}
			}
		}
	}

	return findings
}

var sensitiveEnvVars = map[string]bool{
	"NPM_TOKEN": true, "NODE_AUTH_TOKEN": true, "GITHUB_TOKEN": true,
	"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true,
	"DOCKER_PASSWORD": true, "CI_JOB_TOKEN": true, "GITLAB_TOKEN": true,
	"HEROKU_API_KEY": true, "STRIPE_SECRET_KEY": true, "DATABASE_URL": true,
	"PRIVATE_KEY": true, "SECRET_KEY": true, "API_KEY": true, "PASSWORD": true,
}

var benignEnvVars = map[string]bool{
	"NODE_ENV": true, "PATH": true, "HOME": true, "TERM": true, "LANG": true,
}

func isSensitiveEnvKey(key string) bool {
	if sensitiveEnvVars[key] {
		return true
	}
	upper := strings.ToUpper(key)
	return strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") ||
		strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "API_KEY")
}

func (a *SandboxAnalyzer) checkEnvAccess(output *sandbox.HarnessOutput) []Finding {
	var findings []Finding
	var accessedSensitive, accessedOther []string
	seen := make(map[string]bool)

	for _, call := range output.Intercepted.ProcessEnv {
		if call.Method != "get" || len(call.Args) == 0 {
			continue
		}
		key := call.Args[0]
		if seen[key] || benignEnvVars[key] {
			continue
		}
		seen[key] = true

		if isSensitiveEnvKey(key) {
			accessedSensitive = append(accessedSensitive, key)
		} else {
			accessedOther = append(accessedOther, key)
		}
	}

	if len(accessedSensitive) > 0 {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_sensitive_env",
			Description:    fmt.Sprintf("The package accessed %d sensitive environment variables: %s", len(accessedSensitive), strings.Join(accessedSensitive, ", ")),
			Severity:       SeverityHigh,
			ExploitExample: "dynamic_env_exploit",
			Remediation:    "dynamic_env_remediation",
		})
	}

	if len(accessedOther) > 5 {
		findings = append(findings, Finding{
			Analyzer: a.Name(), Title: "dynamic_env_enumeration",
			Description: fmt.Sprintf("The package accessed %d environment variables: %s", len(accessedOther), strings.Join(accessedOther, ", ")),
			Severity:    SeverityMedium,
		})
	}

	return findings
}

func truncateArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	result := args[0]
	if len(result) > 100 {
		result = result[:100] + "..."
	}
	return result
}
