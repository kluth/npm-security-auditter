package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// IssuesAnalyzer checks for security-related issues in the package's repository.
type IssuesAnalyzer struct {
	httpClient     *http.Client
	githubBaseURL  string
}

func NewIssuesAnalyzer() *IssuesAnalyzer {
	return &IssuesAnalyzer{
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		githubBaseURL: "https://api.github.com",
	}
}

func (a *IssuesAnalyzer) Name() string {
	return "repository-issues"
}

func (a *IssuesAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	repoURL := ""
	if pkg.Repository != nil && pkg.Repository.URL != "" {
		repoURL = pkg.Repository.URL
	} else if version.Repository != nil && version.Repository.URL != "" {
		repoURL = version.Repository.URL
	}

	if repoURL == "" {
		return findings, nil
	}

	owner, repo, platform := parseRepoURL(repoURL)
	if platform == "github" {
		ghFindings := a.checkGitHubIssues(ctx, owner, repo)
		findings = append(findings, ghFindings...)
	}

	return findings, nil
}

type ghIssue struct {
	Title string `json:"title"`
	URL   string `json:"html_url"`
	State string `json:"state"`
}

func (a *IssuesAnalyzer) checkGitHubIssues(ctx context.Context, owner, repo string) []Finding {
	var findings []Finding

	// We'll search for issues with "security", "malware", "compromised", "vulnerability"
	query := fmt.Sprintf("security malware compromised vulnerability hijack")
	keywords := strings.Fields(query)

	apiURL := fmt.Sprintf("%s/repos/%s/%s/issues?state=open&per_page=100", a.githubBaseURL, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}

	var issues []ghIssue
	if err := json.Unmarshal(body, &issues); err != nil {
		return nil
	}

	// Keywords that indicate a critical security issue (not just discussion)
	criticalPatterns := []string{"cve-", "rce", "exploit", "hijack", "breach", "pwn", "compromised", "malware", "backdoor"}

	for _, issue := range issues {
		lowerTitle := strings.ToLower(issue.Title)
		for _, kw := range keywords {
			if strings.Contains(lowerTitle, kw) {
				// Determine severity based on whether it looks like an active threat
				severity := SeverityLow // Default: informational
				for _, critPattern := range criticalPatterns {
					if strings.Contains(lowerTitle, critPattern) {
						severity = SeverityHigh
						break
					}
				}

				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       fmt.Sprintf("Security-related issue found: %s", kw),
					Description: fmt.Sprintf("An open issue mentions %q: %q. See: %s", kw, issue.Title, issue.URL),
					Severity:    severity,
				})
				break
			}
		}
	}

	return findings
}
