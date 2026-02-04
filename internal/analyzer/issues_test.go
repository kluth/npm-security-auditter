package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestIssuesAnalyzer_NoRepo(t *testing.T) {
	a := NewIssuesAnalyzer()
	pkg := &registry.PackageMetadata{}
	ver := &registry.PackageVersion{}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no repo, got %d", len(findings))
	}
}

func TestIssuesAnalyzer_VersionRepoFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/issues", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.github.v3+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"title": "security concern", "html_url": "https://github.com/owner/repo/issues/1", "state": "open"}
		]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	a := NewIssuesAnalyzer()
	a.httpClient = server.Client()
	a.githubBaseURL = server.URL

	// No pkg repo, but version has one
	pkg := &registry.PackageMetadata{}
	ver := &registry.PackageVersion{
		Repository: &registry.Repository{URL: "https://github.com/owner/repo"},
	}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestIssuesAnalyzer_NonGitHub(t *testing.T) {
	a := NewIssuesAnalyzer()
	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "https://gitlab.com/owner/repo"},
	}
	ver := &registry.PackageVersion{}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	// Non-github repos are silently skipped
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-github, got %d", len(findings))
	}
}

func TestIssuesAnalyzer_GitHubAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/issues", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	a := NewIssuesAnalyzer()
	a.httpClient = server.Client()
	a.githubBaseURL = server.URL

	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "https://github.com/owner/repo"},
	}
	ver := &registry.PackageVersion{}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for API error, got %d", len(findings))
	}
}

func TestIssuesAnalyzer_InvalidJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/issues", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	a := NewIssuesAnalyzer()
	a.httpClient = server.Client()
	a.githubBaseURL = server.URL

	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{URL: "https://github.com/owner/repo"},
	}
	ver := &registry.PackageVersion{}

	findings, err := a.Analyze(context.Background(), pkg, ver)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid JSON, got %d", len(findings))
	}
}

func TestIssuesAnalyzer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/issues", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.github.v3+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"title": "security vulnerability in parser", "html_url": "https://github.com/owner/repo/issues/1", "state": "open"},
			{"title": "malware detected", "html_url": "https://github.com/owner/repo/issues/2", "state": "open"},
			{"title": "bug: typo in readme", "html_url": "https://github.com/owner/repo/issues/3", "state": "open"}
		]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	a := NewIssuesAnalyzer()
	a.httpClient = server.Client()
	a.githubBaseURL = server.URL

	pkg := &registry.PackageMetadata{
		Repository: &registry.Repository{
			URL: "https://github.com/owner/repo",
		},
	}
	version := &registry.PackageVersion{}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}

	foundSecurity := false
	foundMalware := false
	for _, f := range findings {
		if f.Title == "Security-related issue found: security" {
			foundSecurity = true
		}
		if f.Title == "Security-related issue found: malware" {
			foundMalware = true
		}
	}

	if !foundSecurity {
		t.Error("did not find security issue")
	}
	if !foundMalware {
		t.Error("did not find malware issue")
	}
}
