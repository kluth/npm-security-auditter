package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matthias/auditter/internal/registry"
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
