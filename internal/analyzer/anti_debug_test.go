package analyzer

import (
	"strings"
	"testing"
)

func TestAntiDebugAnalyzer_DebuggerStatement(t *testing.T) {
	a := NewAntiDebugAnalyzer()
	content := `
function check() {
	debugger;
	debugger;
	debugger;
	// infinite debugger trap
}
setInterval(check, 100);
`
	findings := a.scanContent(content, "trap.js")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "debugger") || strings.Contains(f.Title, "Debugger") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect debugger trap")
	}
}

func TestAntiDebugAnalyzer_TimingCheck(t *testing.T) {
	a := NewAntiDebugAnalyzer()
	content := `
const start = Date.now();
// some operation
const elapsed = Date.now() - start;
if (elapsed > 100) {
	process.exit(1); // debugger detected via timing
}
`
	findings := a.scanContent(content, "timing.js")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Timing") || strings.Contains(f.Title, "timing") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect timing-based debug detection")
	}
}

func TestAntiDebugAnalyzer_ConsoleOverride(t *testing.T) {
	a := NewAntiDebugAnalyzer()
	content := `
console.log = function() {};
console.warn = function() {};
console.error = function() {};
`
	findings := a.scanContent(content, "noconsole.js")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "console") || strings.Contains(f.Title, "Console") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect console override")
	}
}

func TestAntiDebugAnalyzer_ProcessExitOnDetection(t *testing.T) {
	a := NewAntiDebugAnalyzer()
	content := `
if (typeof v8debug === 'object' || /--debug|--inspect/.test(process.execArgv.join(' '))) {
	process.exit(0);
}
`
	findings := a.scanContent(content, "exit.js")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "debug") || strings.Contains(f.Title, "inspect") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect debug/inspect flag detection")
	}
}

func TestAntiDebugAnalyzer_CleanCode(t *testing.T) {
	a := NewAntiDebugAnalyzer()
	content := `
const express = require('express');
const app = express();
console.log('Server starting...');
app.listen(3000);
`
	findings := a.scanContent(content, "clean.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
