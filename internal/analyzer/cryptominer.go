package analyzer

import (
	"fmt"
	"regexp"
)

// CryptominerAnalyzer detects cryptocurrency mining software installation,
// mining pool connections, and in-process mining via WASM. Distinct from
// crypto_theft.go which focuses on wallet theft; this focuses on resource
// hijacking for mining. Based on XMRig deployments via npm packages and
// VS Code extensions (2024), and CrowdStrike WASM mining research.
type CryptominerAnalyzer struct{}

func NewCryptominerAnalyzer() *CryptominerAnalyzer {
	return &CryptominerAnalyzer{}
}

func (a *CryptominerAnalyzer) Name() string {
	return "cryptominer"
}

var cryptominerPatterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// Mining software binaries
	{
		regexp.MustCompile(`(?i)\b(xmrig|xmr-stak|minergate|ethminer|nbminer|cgminer|cpuminer|bfgminer|minerd|nicehash)\b`),
		"Cryptocurrency mining software",
		"Code references a known cryptocurrency mining binary",
		SeverityCritical,
	},
	// Mining pool URLs
	{
		regexp.MustCompile(`(?i)stratum\+(?:tcp|ssl|tls)://`),
		"Mining pool stratum protocol",
		"Code connects to a mining pool using the stratum protocol, the standard for cryptocurrency mining",
		SeverityCritical,
	},
	// Known mining pool domains
	{
		regexp.MustCompile(`(?i)(?:pool\.minexmr\.com|xmr\.pool\.minergate\.com|monerohash\.com|moneropool\.com|nanopool\.org|supportxmr\.com|hashvault\.pro|2miners\.com|f2pool\.com|antpool\.com)`),
		"Known mining pool domain",
		"Code connects to a recognized cryptocurrency mining pool",
		SeverityCritical,
	},
	// CPU/GPU usage maximization patterns
	{
		regexp.MustCompile(`(?i)(?:os\.cpus|require\s*\(\s*['"]os['"]\s*\)[\s\S]{0,100}cpus)\s*\(\s*\)[\s\S]{0,100}(?:worker|thread|fork|cluster)`),
		"CPU core enumeration for parallelism",
		"Code enumerates CPU cores and creates parallel workers, a pattern used by mining software to maximize hash rate",
		SeverityMedium,
	},
	// Monero wallet address (44-char base58)
	{
		regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`),
		"Monero wallet address",
		"Code contains a Monero wallet address, the most common cryptocurrency target for npm-based miners",
		SeverityHigh,
	},
	// Mining configuration patterns
	{
		regexp.MustCompile(`(?i)["'](?:algo|coin)["']\s*:\s*["'](?:cryptonight|randomx|ethash|kawpow|equihash|scrypt)["']`),
		"Mining algorithm configuration",
		"Code contains cryptocurrency mining algorithm configuration",
		SeverityCritical,
	},
	// Worker/hash rate terminology
	{
		regexp.MustCompile(`(?i)(?:hashrate|hash_rate|hashes_per_second|h/s|kh/s|mh/s|gh/s)\b`),
		"Mining hash rate reference",
		"Code references mining hash rates, indicating active cryptocurrency mining",
		SeverityHigh,
	},
	// Process hiding for miners
	{
		regexp.MustCompile(`(?i)process\.title\s*=\s*['"](?:node|npm|yarn|webpack|babel|tsc)['"]`),
		"Process name disguise",
		"Code disguises the process name as a legitimate tool, a technique used by miners to avoid detection in task managers",
		SeverityHigh,
	},
}

func (a *CryptominerAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range cryptominerPatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "Cryptojacking via npm packages:\n" +
					"    1. Package postinstall downloads XMRig or WASM miner\n" +
					"    2. Miner connects to pool: stratum+tcp://pool.minexmr.com:4444\n" +
					"    3. CPU/GPU resources consumed for Monero mining\n" +
					"    4. Process disguised as 'node' or 'npm' in task manager\n" +
					"    CrowdStrike: 75% of WASM modules are cryptominers\n" +
					"    10 VS Code extensions deployed XMRig (2024)",
				Remediation: "Remove the package immediately. Check for running mining processes and unauthorized CPU usage spikes.",
			})
		}
	}

	return findings
}
