package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
)

func TestCalculateRiskScore(t *testing.T) {
	tests := []struct {
		name    string
		results []analyzer.Result
		want    int
	}{
		{
			name:    "no findings",
			results: nil,
			want:    0,
		},
		{
			name: "single low",
			results: []analyzer.Result{
				{Findings: []analyzer.Finding{{Severity: analyzer.SeverityLow}}},
			},
			want: 2,
		},
		{
			name: "single critical",
			results: []analyzer.Result{
				{Findings: []analyzer.Finding{{Severity: analyzer.SeverityCritical}}},
			},
			want: 25,
		},
		{
			name: "mixed findings",
			results: []analyzer.Result{
				{Findings: []analyzer.Finding{
					{Severity: analyzer.SeverityCritical},
					{Severity: analyzer.SeverityHigh},
					{Severity: analyzer.SeverityMedium},
					{Severity: analyzer.SeverityLow},
				}},
			},
			want: 47, // 25 + 15 + 5 + 2
		},
		{
			name: "capped at 100",
			results: []analyzer.Result{
				{Findings: []analyzer.Finding{
					{Severity: analyzer.SeverityCritical},
					{Severity: analyzer.SeverityCritical},
					{Severity: analyzer.SeverityCritical},
					{Severity: analyzer.SeverityCritical},
					{Severity: analyzer.SeverityCritical},
				}},
			},
			want: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateRiskScore(tt.results)
			if got != tt.want {
				t.Errorf("CalculateRiskScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRenderTerminal(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	report := Report{
		Package: "test-pkg",
		Version: "1.0.0",
		Results: []analyzer.Result{
			{
				AnalyzerName: "test-analyzer",
				Findings: []analyzer.Finding{
					{
						Analyzer:    "test-analyzer",
						Title:       "Test Issue",
						Description: "A test finding",
						Severity:    analyzer.SeverityHigh,
					},
				},
			},
		},
	}

	err := r.Render(report)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test-pkg") {
		t.Error("output should contain package name")
	}
	if !strings.Contains(output, "Test Issue") {
		t.Error("output should contain finding title")
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatJSON, LangEN)

	report := Report{
		Package: "test-pkg",
		Version: "1.0.0",
		Results: []analyzer.Result{
			{
				AnalyzerName: "test-analyzer",
				Findings: []analyzer.Finding{
					{
						Analyzer:    "test-analyzer",
						Title:       "Test Issue",
						Description: "A test finding",
						Severity:    analyzer.SeverityHigh,
					},
				},
			},
		},
	}

	err := r.Render(report)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	var parsed Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}
	if parsed.Package != "test-pkg" {
		t.Errorf("JSON package = %q, want %q", parsed.Package, "test-pkg")
	}
}

func TestRenderNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	report := Report{
		Package: "safe-pkg",
		Version: "2.0.0",
		Results: []analyzer.Result{
			{AnalyzerName: "test", Findings: nil},
		},
	}

	err := r.Render(report)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No issues found") {
		t.Error("output should indicate no issues found")
	}
}

func TestRenderWithErrors(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	report := Report{
		Package: "err-pkg",
		Version: "1.0.0",
		Results: []analyzer.Result{
			{
				AnalyzerName: "failing-analyzer",
				Err:          errors.New("connection timeout"),
			},
		},
	}

	err := r.Render(report)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "failing-analyzer") {
		t.Error("output should mention the failing analyzer")
	}
}

func TestSeverityHelpers(t *testing.T) {
	tests := []struct {
		s    analyzer.Severity
		wantColor string
		wantIcon  string
	}{
		{analyzer.SeverityCritical, colorRed, "✖"},
		{analyzer.SeverityHigh, colorRed, "!"},
		{analyzer.SeverityMedium, colorYellow, "~"},
		{analyzer.SeverityLow, colorDim, "-"},
	}

	for _, tt := range tests {
		if got := severityColor(tt.s); got != tt.wantColor {
			t.Errorf("severityColor(%q) = %q, want %q", tt.s, got, tt.wantColor)
		}
		if got := severityIcon(tt.s); got != tt.wantIcon {
			t.Errorf("severityIcon(%q) = %q, want %q", tt.s, got, tt.wantIcon)
		}
	}
}

func TestRiskLevel(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)
	tests := []struct {
		score int
		wantColor string
		wantLabel string
	}{
		{100, colorRed, "CRITICAL RISK"},
		{70, colorRed, "CRITICAL RISK"},
		{69, colorYellow, "MODERATE RISK"},
		{40, colorYellow, "MODERATE RISK"},
		{39, colorBlue, "ELEVATED RISK"},
		{20, colorBlue, "ELEVATED RISK"},
		{19, colorGreen, "LOW RISK"},
		{0, colorGreen, "LOW RISK"},
	}

	for _, tt := range tests {
		color, label := r.GetRiskLevel(tt.score)
		if color != tt.wantColor {
			t.Errorf("GetRiskLevel(%d) color = %q, want %q", tt.score, color, tt.wantColor)
		}
		if label != tt.wantLabel {
			t.Errorf("GetRiskLevel(%d) label = %q, want %q", tt.score, label, tt.wantLabel)
		}
	}
}

func TestPluralize(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)
	if r.pluralize("test", 1) != "test" {
		t.Error("pluralize(test, 1) should be test")
	}
	if r.pluralize("test", 2) != "tests" {
		t.Error("pluralize(test, 2) should be tests")
	}
}

func TestPrintWrapped(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	r.printWrapped(&buf, "this is a very long text that should be wrapped", "  ", 20)
	
	lines := strings.Split(buf.String(), "\n")
	for _, line := range lines {
		if len(line) > 20 && line != "" {
			t.Errorf("line exceeds width: %q", line)
		}
	}
}

func TestSeverityColorForCount(t *testing.T) {
	arg := struct {
		name     string
		total    int
		critical int
		high     int
		medium   int
		low      int
	}{critical: 1}
	if severityColorForCount(arg) != colorRed {
		t.Error("expected colorRed for critical")
	}
}

func TestGenerateRecommendations(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)
	recs := r.generateRecommendations(70, nil)
	found := false
	for _, rec := range recs {
		if strings.Contains(rec, "DO NOT install") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected recommendation for critical risk")
	}
}

func TestKlingon(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangTLH)
	report := Report{
		Package: "klingon-pkg",
		Version: "1.0.0",
	}
	r.Render(report)
	if !strings.Contains(buf.String(), "npm QaD Qu' 'oH") {
		t.Error("expected Klingon title")
	}
}

func TestVulcan(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangVUL)
	report := Report{
		Package: "vulcan-pkg",
		Version: "1.0.0",
	}
	r.Render(report)
	if !strings.Contains(buf.String(), "Probability Analysis") {
		t.Error("expected Vulcan risk assessment label")
	}
}

func TestMarkdown(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatMarkdown, LangEN)
	report := Report{
		Package: "md-pkg",
		Version: "1.0.0",
	}
	r.Render(report)
	if !strings.HasPrefix(buf.String(), "#") {
		t.Error("expected Markdown header")
	}
}

func TestHTML(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatHTML, LangEN)
	report := Report{
		Package: "html-pkg",
		Version: "1.0.0",
	}
	r.Render(report)
	if !strings.Contains(buf.String(), "<html>") {
		t.Error("expected HTML tags")
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatCSV, LangEN)
	report := Report{
		Package: "csv-pkg",
		Version: "1.0.0",
		Results: []analyzer.Result{
			{
				Findings: []analyzer.Finding{
					{Severity: analyzer.SeverityHigh, Analyzer: "test", Title: "Issue", Description: "Desc"},
				},
			},
		},
	}
	r.Render(report)
	if !strings.Contains(buf.String(), "Severity,Analyzer,Title,Description") {
		t.Error("expected CSV header")
	}
	if !strings.Contains(buf.String(), "HIGH,test,\"Issue\",\"Desc\"") {
		t.Error("expected CSV data")
	}
}