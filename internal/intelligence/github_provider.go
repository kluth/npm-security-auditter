package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
)

// GitHubProvider fetches malicious package lists from a GitHub repository.
type GitHubProvider struct {
	client *http.Client
	url    string
}

// NewGitHubProvider creates a new GitHub intelligence provider.
func NewGitHubProvider(url string) *GitHubProvider {
	if url == "" {
		// Use a community-maintained list as default
		// Example: Phylum's research or a curated list
		url = "https://raw.githubusercontent.com/kluth/npm-malicious-packages/main/list.json"
	}
	return &GitHubProvider{
		client: &http.Client{Timeout: 30 * time.Second},
		url:    url,
	}
}

func (p *GitHubProvider) Name() string { return "github-malicious-list" }

func (p *GitHubProvider) Fetch(ctx context.Context) ([]IntelIssue, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// If the default URL doesn't exist yet, we return an empty list instead of failing
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var rawIssues []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawIssues); err != nil {
		return nil, err
	}

	var issues []IntelIssue
	for _, ri := range rawIssues {
		issues = append(issues, IntelIssue{
			ID:          "MAL-" + ri.Name,
			Type:        IssueTypeMaliciousPackage,
			Target:      ri.Name,
			Description: ri.Description,
			Severity:    parseSeverity(ri.Severity),
			Source:      p.url,
			UpdatedAt:   time.Now(),
		})
	}

	return issues, nil
}

func parseSeverity(s string) analyzer.Severity {
	switch s {
	case "critical":
		return analyzer.SeverityCritical
	case "high":
		return analyzer.SeverityHigh
	case "medium":
		return analyzer.SeverityMedium
	default:
		return analyzer.SeverityLow
	}
}
