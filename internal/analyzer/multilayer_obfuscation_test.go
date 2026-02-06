package analyzer

import (
	"strings"
	"testing"
)

func TestMultilayerObfuscation_NestedEval(t *testing.T) {
	a := NewMultilayerObfuscationAnalyzer()
	content := `eval(eval(atob('ZXZhbChhdG9iKCdZM1Z5YkNBdGN5Qm9kSFJ3T2k4dlpYWnBiQzVqYjIwPScpKQ==')));`
	findings := a.scanContent(content, "nested.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Nested") || strings.Contains(f.Title, "nested") || strings.Contains(f.Title, "multi-layer") {
			found = true
			if f.Severity < SeverityCritical {
				t.Errorf("Expected CRITICAL severity for nested eval, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect nested eval chain")
	}
}

func TestMultilayerObfuscation_XORCipher(t *testing.T) {
	a := NewMultilayerObfuscationAnalyzer()
	content := `
const key = 42;
const encoded = [0x4b, 0x47, 0x5e, 0x5e, 0x45];
const decoded = encoded.map(c => String.fromCharCode(c ^ key)).join('');
eval(decoded);
`
	findings := a.scanContent(content, "xor.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "XOR") || strings.Contains(f.Title, "xor") || strings.Contains(f.Title, "cipher") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect XOR cipher obfuscation")
	}
}

func TestMultilayerObfuscation_SelfDecodingWrapper(t *testing.T) {
	a := NewMultilayerObfuscationAnalyzer()
	content := `
(function(){var a=function(b){return decodeURIComponent(escape(atob(b)))};eval(a('dmFyIHg9InJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKSI='));})();
`
	findings := a.scanContent(content, "self_decode.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "self-decod") || strings.Contains(f.Title, "Self-decod") || strings.Contains(f.Title, "wrapper") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect self-decoding wrapper pattern")
	}
}

func TestMultilayerObfuscation_HexEscapeChain(t *testing.T) {
	a := NewMultilayerObfuscationAnalyzer()
	content := `
const a = "\x72\x65\x71\x75\x69\x72\x65";
const b = "\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73";
global[a](b)["\x65\x78\x65\x63"]("\x77\x68\x6f\x61\x6d\x69");
`
	findings := a.scanContent(content, "hex_chain.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "hex") || strings.Contains(f.Title, "Hex") || strings.Contains(f.Title, "escape") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect heavy hex escape usage")
	}
}

func TestMultilayerObfuscation_UnicodeObfuscation(t *testing.T) {
	a := NewMultilayerObfuscationAnalyzer()
	// Japanese Katakana characters used as variable names (seen in real malware)
	content := `
const アイウ = '\x65\x76\x61\x6c';
const エオカ = '\x72\x65\x71\x75\x69\x72\x65';
globalThis[アイウ](globalThis[エオカ]('child_process'));
`
	findings := a.scanContent(content, "unicode.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Unicode") || strings.Contains(f.Title, "unicode") || strings.Contains(f.Title, "Non-ASCII") || strings.Contains(f.Title, "non-ASCII") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect non-ASCII identifier obfuscation")
	}
}

func TestMultilayerObfuscation_CleanCode(t *testing.T) {
	a := NewMultilayerObfuscationAnalyzer()
	content := `
const http = require('http');
const server = http.createServer((req, res) => {
	res.writeHead(200);
	res.end('Hello World');
});
server.listen(3000);
`
	findings := a.scanContent(content, "clean.js")

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
