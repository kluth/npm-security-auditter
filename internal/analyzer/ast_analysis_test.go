package analyzer

import (
	"strings"
	"testing"
)

func TestASTAnalyzer_DynamicRequire(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const name = 'child' + '_process';
const cp = require(name);
cp.exec('rm -rf /');
`
	findings := a.scanContent(content, "dynamic.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Dynamic require") || strings.Contains(f.Title, "dynamic") {
			found = true
			if f.Severity < SeverityHigh {
				t.Errorf("Expected HIGH+ severity for dynamic require, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect dynamic require pattern")
	}
}

func TestASTAnalyzer_ComputedPropertyAccess(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const fn = 'ex' + 'ec';
require('child_process')[fn]('whoami');
`
	findings := a.scanContent(content, "computed.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Computed") || strings.Contains(f.Title, "property") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect computed property access")
	}
}

func TestASTAnalyzer_StringConcatObfuscation(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const a = 'ch' + 'il' + 'd_' + 'pr' + 'oc' + 'es' + 's';
const b = require(a);
`
	findings := a.scanContent(content, "concat.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "String concat") || strings.Contains(f.Title, "obfuscation") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect string concatenation obfuscation")
	}
}

func TestASTAnalyzer_ArrayJoinObfuscation(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const parts = ['child', '_', 'process'];
const mod = require(parts.join(''));
`
	findings := a.scanContent(content, "arrayjoin.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Array join") || strings.Contains(f.Title, "obfuscation") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect array join obfuscation")
	}
}

func TestASTAnalyzer_GlobalThisAccess(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const g = globalThis || global || window;
g['ev' + 'al'](payload);
`
	findings := a.scanContent(content, "globalthis.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "global") || strings.Contains(f.Title, "Global") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect globalThis/global access pattern")
	}
}

func TestASTAnalyzer_ProxyHandler(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const handler = {
	get: function(target, prop) {
		return Reflect.get(target, prop);
	}
};
const proxy = new Proxy(require, handler);
proxy('child_process');
`
	findings := a.scanContent(content, "proxy.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Proxy") || strings.Contains(f.Title, "proxy") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect Proxy-based require wrapping")
	}
}

func TestASTAnalyzer_FunctionConstructor(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const fn = new Function('return process.env');
const env = fn();
`
	findings := a.scanContent(content, "funcctor.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Function constructor") || strings.Contains(f.Title, "Constructor") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect Function constructor")
	}
}

func TestASTAnalyzer_CleanCode(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/', (req, res) => {
	res.send('Hello World');
});
app.listen(3000);
`
	findings := a.scanContent(content, "clean.js")

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}

func TestASTAnalyzer_CharCodeObfuscation(t *testing.T) {
	a := NewASTAnalyzer()
	content := `
const s = String.fromCharCode(101, 118, 97, 108);
globalThis[s](payload);
`
	findings := a.scanContent(content, "charcode.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "CharCode") || strings.Contains(f.Title, "charCode") || strings.Contains(f.Title, "character code") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect String.fromCharCode obfuscation")
	}
}
