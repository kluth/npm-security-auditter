package analyzer

import (
	"fmt"
	"regexp"
)

// SocksProxyAnalyzer detects SOCKS proxy setup, network tunneling, and
// port forwarding that enables attackers to route traffic through the
// victim's network for lateral movement and internal resource access.
type SocksProxyAnalyzer struct{}

func NewSocksProxyAnalyzer() *SocksProxyAnalyzer {
	return &SocksProxyAnalyzer{}
}

func (a *SocksProxyAnalyzer) Name() string {
	return "socks-proxy"
}

var socksProxyPatterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// SOCKS protocol references
	{
		regexp.MustCompile(`(?i)socks[45]?://`),
		"SOCKS proxy URL",
		"Code contains a SOCKS proxy URL, which can route attacker traffic through the victim's network",
		SeverityHigh,
	},
	// SOCKS npm packages
	{
		regexp.MustCompile(`require\s*\(\s*['"](?:socks|socks-proxy-agent|socksv5|socks5-http-client)['"]\s*\)`),
		"SOCKS proxy library import",
		"Code imports a SOCKS proxy library for network tunneling",
		SeverityHigh,
	},
	// Port forwarding tools
	{
		regexp.MustCompile(`(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"](?:ngrok|frp|frps|frpc|chisel|bore)\b`),
		"Tunneling tool execution",
		"Code executes a network tunneling tool (ngrok, frp, chisel), enabling remote access through firewalls",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`\b(?:ngrok|frpc?s?|chisel|bore)\s+(?:http|tcp|start|server|client)\b`),
		"Tunneling tool command",
		"Code invokes a tunneling tool command for remote access through firewalls",
		SeverityCritical,
	},
	// SSH SOCKS proxy (dynamic forwarding)
	{
		regexp.MustCompile(`ssh\s+.*-D\s+\d+`),
		"SSH SOCKS proxy",
		"Code creates an SSH dynamic port forward (SOCKS proxy) for network tunneling",
		SeverityHigh,
	},
	// Local port forwarding
	{
		regexp.MustCompile(`ssh\s+.*-L\s+\d+:`),
		"SSH local port forward",
		"Code creates an SSH local port forward, potentially exposing internal services",
		SeverityHigh,
	},
	// Common proxy ports
	{
		regexp.MustCompile(`(?:listen|bind|createServer)\s*\(\s*(?:1080|9050|9150|8080)\s*[,)]`),
		"Common proxy port binding",
		"Code binds to a well-known proxy port (1080=SOCKS, 9050=Tor, 8080=HTTP proxy)",
		SeverityMedium,
	},
	// Tor integration
	{
		regexp.MustCompile(`require\s*\(\s*['"](?:tor-request|tor-axios|granax|node-tor-control)['"]\s*\)`),
		"Tor network integration",
		"Code imports Tor network libraries for anonymous routing, potentially hiding C2 communication",
		SeverityHigh,
	},
	// Proxy chain setup
	{
		regexp.MustCompile(`(?i)(?:proxy_?chain|proxychains)`),
		"Proxy chain configuration",
		"Code references proxy chaining, used to obfuscate the source of network connections",
		SeverityHigh,
	},
}

func (a *SocksProxyAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range socksProxyPatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "Network proxy/tunnel attacks route traffic through victim networks:\n" +
					"    - SOCKS proxy: attacker routes traffic through compromised machine\n" +
					"    - SSH tunnel: encrypted tunnel bypasses firewall inspection\n" +
					"    - ngrok/frp: expose internal services through tunneling service\n" +
					"    - Tor: anonymize C2 communication to avoid attribution\n" +
					"    Used for lateral movement, internal recon, and C2 routing",
				Remediation: "npm packages should never set up network proxies or tunnels. Remove immediately and check for active tunneling processes.",
			})
		}
	}

	return findings
}
