package analyzer

import "regexp"

// maliciousJSPattern defines a pattern to detect in JS/TS source files.
type maliciousJSPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity Severity
}

// maliciousJSPatterns detects suspicious code in JavaScript/TypeScript files.
var maliciousJSPatterns = []maliciousJSPattern{
	{
		Name:     "child_process require",
		Pattern:  regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)`),
		Severity: SeverityCritical,
	},
	{
		Name:     "child_process import",
		Pattern:  regexp.MustCompile(`import\s+.*from\s+['"]child_process['"]`),
		Severity: SeverityCritical,
	},
	{
		Name:     "exec/spawn call",
		Pattern:  regexp.MustCompile(`\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(`),
		Severity: SeverityHigh,
	},
	{
		Name:     "eval usage",
		Pattern:  regexp.MustCompile(`\beval\s*\(`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Function constructor",
		Pattern:  regexp.MustCompile(`new\s+Function\s*\(`),
		Severity: SeverityHigh,
	},
	{
		Name:     "DNS operations",
		Pattern:  regexp.MustCompile(`require\s*\(\s*['"]dns['"]\s*\)`),
		Severity: SeverityHigh,
	},
	{
		Name:     "process.env access",
		Pattern:  regexp.MustCompile(`process\.env\b`),
		Severity: SeverityMedium,
	},
	{
		Name:     "credential path access",
		Pattern:  regexp.MustCompile(`['"](/etc/passwd|/etc/shadow|\.ssh/|\.npmrc|\.env|\.aws/credentials|\.docker/config|\.kube/config)['"]`),
		Severity: SeverityCritical,
	},
	{
		Name:     "network request",
		Pattern:  regexp.MustCompile(`require\s*\(\s*['"](http|https|net|dgram|tls)['"]\s*\)`),
		Severity: SeverityMedium,
	},
	{
		Name:     "fetch API",
		Pattern:  regexp.MustCompile(`\bfetch\s*\(\s*['"]https?://`),
		Severity: SeverityMedium,
	},
	{
		Name:     "XMLHttpRequest",
		Pattern:  regexp.MustCompile(`new\s+XMLHttpRequest`),
		Severity: SeverityMedium,
	},
	{
		Name:     "curl/wget in string",
		Pattern:  regexp.MustCompile(`['"].*\b(curl|wget)\s+`),
		Severity: SeverityHigh,
	},
	{
		Name:     "base64 decode",
		Pattern:  regexp.MustCompile(`Buffer\.from\s*\([^,]+,\s*['"]base64['"]\)`),
		Severity: SeverityMedium,
	},
	{
		Name:     "hex decode in buffer",
		Pattern:  regexp.MustCompile(`Buffer\.from\s*\([^,]+,\s*['"]hex['"]\)`),
		Severity: SeverityMedium,
	},
	{
		Name:     "environment exfiltration",
		Pattern:  regexp.MustCompile(`JSON\.stringify\s*\(\s*process\.env\s*\)`),
		Severity: SeverityCritical,
	},
	{
		Name:     "dynamic require",
		Pattern:  regexp.MustCompile(`require\s*\(\s*[^'"]\S+\s*\+`),
		Severity: SeverityMedium,
	},
}

// cryptoWalletPattern detects cryptocurrency wallet addresses.
type cryptoWalletPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// cryptoWalletPatterns matches common cryptocurrency address formats.
var cryptoWalletPatterns = []cryptoWalletPattern{
	{
		Name:    "Bitcoin address",
		Pattern: regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`),
	},
	{
		Name:    "Bitcoin Bech32 address",
		Pattern: regexp.MustCompile(`\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b`),
	},
	{
		Name:    "Ethereum address",
		Pattern: regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`),
	},
	{
		Name:    "Monero address",
		Pattern: regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`),
	},
}

// knownMalwareSignature holds a byte sequence from known npm malware.
type knownMalwareSignature struct {
	Name      string
	Signature []byte
}

// knownMalwareSignatures are byte sequences found in known npm malware samples.
var knownMalwareSignatures = []knownMalwareSignature{
	{
		Name:      "flatmap-stream payload marker",
		Signature: []byte("e.exports=function(e,t,n)"),
	},
	{
		Name:      "event-stream/flatmap injection",
		Signature: []byte("./test/data"),
	},
	{
		Name:      "ua-parser-js crypto miner marker",
		Signature: []byte("jsextension"),
	},
	{
		Name:      "rc/systeminformation exfil",
		Signature: []byte("sstatic1.histats.com"),
	},
	{
		Name:      "coa malware marker",
		Signature: []byte("sdd.dll"),
	},
}

// binaryMagic detects compiled binary files by their magic bytes.
type binaryMagic struct {
	Name  string
	Magic []byte
}

// binaryMagicBytes are file signatures for compiled executables.
var binaryMagicBytes = []binaryMagic{
	{Name: "ELF binary", Magic: []byte{0x7f, 0x45, 0x4c, 0x46}},
	{Name: "PE executable", Magic: []byte{0x4d, 0x5a}},
	{Name: "Mach-O binary (32-bit)", Magic: []byte{0xfe, 0xed, 0xfa, 0xce}},
	{Name: "Mach-O binary (64-bit)", Magic: []byte{0xfe, 0xed, 0xfa, 0xcf}},
	{Name: "Mach-O binary (universal)", Magic: []byte{0xca, 0xfe, 0xba, 0xbe}},
}

// hiddenFileNames are files that should not normally be in an npm package.
var hiddenFileNames = map[string]bool{
	".env":               true,
	".npmrc":             true,
	".ssh":               true,
	".git":               true,
	".aws":               true,
	".docker":            true,
	".kube":              true,
	".bash_history":      true,
	".zsh_history":       true,
	".netrc":             true,
	".pgpass":            true,
	".mysql_history":     true,
	".psql_history":      true,
	".gitconfig":         true,
	".config":            true,
}
