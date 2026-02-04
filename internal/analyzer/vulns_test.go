package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestVulnAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		response     osvResponse
		statusCode   int
		wantFindings int
		wantErr      bool
	}{
		{
			name:         "no vulnerabilities",
			response:     osvResponse{Vulns: nil},
			statusCode:   http.StatusOK,
			wantFindings: 0,
		},
		{
			name: "one vulnerability",
			response: osvResponse{
				Vulns: []osvVuln{
					{
						ID:      "GHSA-1234-5678",
						Summary: "Prototype pollution in test-pkg",
						Severity: []osvSeverity{
							{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
						},
					},
				},
			},
			statusCode:   http.StatusOK,
			wantFindings: 1,
		},
		{
			name: "multiple vulnerabilities",
			response: osvResponse{
				Vulns: []osvVuln{
					{ID: "CVE-2023-001", Summary: "XSS vulnerability"},
					{ID: "CVE-2023-002", Summary: "RCE vulnerability"},
				},
			},
			statusCode:   http.StatusOK,
			wantFindings: 2,
		},
		{
			name:       "API error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.response)
				}
			}))
			defer server.Close()

			analyzer := NewVulnAnalyzer()
			analyzer.osvURL = server.URL

			pkg := &registry.PackageMetadata{Name: "test-pkg"}
			ver := &registry.PackageVersion{Version: "1.0.0"}

			findings, err := analyzer.Analyze(context.Background(), pkg, ver)
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("Analyze() returned %d findings, want %d", len(findings), tt.wantFindings)
			}
		})
	}
}

func TestVulnAnalyzer_EmptySummaryFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(osvResponse{
			Vulns: []osvVuln{
				{
					ID:      "GHSA-empty-summary",
					Summary: "",
					Details: "This vulnerability allows remote code execution",
				},
			},
		})
	}))
	defer server.Close()

	a := NewVulnAnalyzer()
	a.osvURL = server.URL
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	ver := &registry.PackageVersion{Version: "1.0.0"}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Description != "This vulnerability allows remote code execution" {
		t.Errorf("expected details as description, got %q", findings[0].Description)
	}
}

func TestVulnAnalyzer_LongDescriptionTruncation(t *testing.T) {
	longDesc := strings.Repeat("A", 250)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(osvResponse{
			Vulns: []osvVuln{
				{
					ID:      "GHSA-long-desc",
					Summary: longDesc,
				},
			},
		})
	}))
	defer server.Close()

	a := NewVulnAnalyzer()
	a.osvURL = server.URL
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	ver := &registry.PackageVersion{Version: "1.0.0"}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].Description) != 203 { // 200 + "..."
		t.Errorf("expected truncated description of 203 chars, got %d", len(findings[0].Description))
	}
	if !strings.HasSuffix(findings[0].Description, "...") {
		t.Error("expected truncated description to end with ...")
	}
}

func TestVulnAnalyzer_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid`))
	}))
	defer server.Close()

	a := NewVulnAnalyzer()
	a.osvURL = server.URL
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	ver := &registry.PackageVersion{Version: "1.0.0"}

	_, err := a.Analyze(context.Background(), pkg, ver)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestVulnAnalyzer_ExploitAndRemediation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(osvResponse{
			Vulns: []osvVuln{
				{
					ID:      "GHSA-test-1234",
					Summary: "Test vulnerability",
					Severity: []osvSeverity{
						{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
					},
				},
			},
		})
	}))
	defer server.Close()

	a := NewVulnAnalyzer()
	a.osvURL = server.URL
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	ver := &registry.PackageVersion{Version: "1.0.0"}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ExploitExample == "" {
		t.Error("expected exploit example to be set")
	}
	if findings[0].Remediation == "" {
		t.Error("expected remediation to be set")
	}
	if !strings.Contains(findings[0].ExploitExample, "GHSA-test-1234") {
		t.Error("exploit example should contain the vuln ID")
	}
	if !strings.Contains(findings[0].Remediation, "test-pkg") {
		t.Error("remediation should contain the package name")
	}
}

func TestVulnAnalyzer_NoSeverity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(osvResponse{
			Vulns: []osvVuln{
				{
					ID:       "GHSA-no-severity",
					Summary:  "No CVSS",
					Severity: nil,
				},
			},
		})
	}))
	defer server.Close()

	a := NewVulnAnalyzer()
	a.osvURL = server.URL
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	ver := &registry.PackageVersion{Version: "1.0.0"}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium for no CVSS, got %v", findings[0].Severity)
	}
}

func TestCvssToSeverity(t *testing.T) {
	tests := []struct {
		score string
		want  Severity
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", SeverityCritical},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", SeverityHigh},
		{"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N", SeverityMedium},
		{"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", SeverityLow},
		{"", SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.score, func(t *testing.T) {
			got := cvssToSeverity(tt.score)
			if got != tt.want {
				t.Errorf("cvssToSeverity(%q) = %v, want %v", tt.score, got, tt.want)
			}
		})
	}
}
