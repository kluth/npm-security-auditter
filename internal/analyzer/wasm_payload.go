package analyzer

import (
	"fmt"
	"regexp"
)

// WasmPayloadAnalyzer detects WebAssembly-based payload delivery and execution.
// WASM binaries are extremely difficult to reverse-engineer and most AV/SAST
// tools cannot analyze them. CrowdStrike found that 75% of WASM modules in
// the wild are malicious; WASMixer obfuscation completely evaded VirusTotal.
type WasmPayloadAnalyzer struct{}

func NewWasmPayloadAnalyzer() *WasmPayloadAnalyzer {
	return &WasmPayloadAnalyzer{}
}

func (a *WasmPayloadAnalyzer) Name() string {
	return "wasm-payload"
}

var wasmPatterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// WebAssembly instantiation
	{
		regexp.MustCompile(`WebAssembly\.(instantiate|compile|instantiateStreaming|compileStreaming)\s*\(`),
		"WebAssembly module instantiation",
		"Code instantiates a WebAssembly module. WASM binaries are opaque to static analysis and 75% of WASM in the wild is malicious (CrowdStrike)",
		SeverityHigh,
	},
	// WASM from base64/hex
	{
		regexp.MustCompile(`(?:Buffer\.from|atob|Uint8Array)\s*\([^)]+\)[\s\S]{0,100}WebAssembly`),
		"WebAssembly from encoded data",
		"Code constructs a WASM module from encoded data at runtime, bypassing file-based detection",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`WebAssembly[\s\S]{0,100}(?:Buffer\.from|atob|Uint8Array)\s*\(`),
		"WebAssembly with encoded data",
		"Code combines WebAssembly APIs with encoded data construction",
		SeverityCritical,
	},
	// WASM module loading from network
	{
		regexp.MustCompile(`(?:fetch|axios|http|https)\s*\([^)]*\.wasm['")\s]`),
		"Remote WASM module loading",
		"Code fetches a WASM module from a remote URL, enabling dynamic payload delivery",
		SeverityHigh,
	},
	// WASM import object with dangerous capabilities
	{
		regexp.MustCompile(`importObject[\s\S]{0,300}(?:child_process|fs\.|net\.|http\.|exec|spawn)`),
		"WASM import with system access",
		"Code provides system-level capabilities (filesystem, network, process execution) to a WASM module",
		SeverityCritical,
	},
	// .wasm file reference
	{
		regexp.MustCompile(`['"][^'"]*\.wasm['"]\s*(?:\)|,|;)`),
		"WASM file reference",
		"Code references a .wasm file. In non-WASM application packages, this may indicate a compiled malicious payload",
		SeverityMedium,
	},
	// WASM memory manipulation
	{
		regexp.MustCompile(`WebAssembly\.Memory\s*\(\s*\{[\s\S]{0,100}(?:shared|maximum)\s*:`),
		"WebAssembly shared memory",
		"Code creates WASM shared memory, which can be used for inter-thread communication in mining or C2 operations",
		SeverityMedium,
	},
}

func (a *WasmPayloadAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range wasmPatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "WebAssembly payload delivery:\n" +
					"    1. Malicious code compiled to WASM (from C/C++/Rust)\n" +
					"    2. WASM binary included in package or fetched at runtime\n" +
					"    3. WebAssembly.instantiate() executes the binary\n" +
					"    4. Static analysis cannot inspect WASM bytecode\n" +
					"    CrowdStrike: 75% of WASM in the wild is malicious\n" +
					"    WASMixer: 11/18 obfuscation combos evaded VirusTotal completely",
				Remediation: "Investigate why this package needs WebAssembly. Decompile the .wasm file with wasm2wat or wasm-decompile for analysis.",
			})
		}
	}

	return findings
}
