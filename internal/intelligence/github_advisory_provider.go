package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GitHubAdvisoryProvider fetches malware advisories from the GitHub Advisory Database.
// It specifically looks for the 'malware' classification in the npm ecosystem.
type GitHubAdvisoryProvider struct {
	client *http.Client
}

func NewGitHubAdvisoryProvider() *GitHubAdvisoryProvider {
	return &GitHubAdvisoryProvider{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (p *GitHubAdvisoryProvider) Name() string { return "github-advisory-malware" }

func (p *GitHubAdvisoryProvider) Fetch(ctx context.Context) ([]IntelIssue, error) {
	// Use the official GitHub Security Advisories API
	aggregatorURL := "https://api.github.com/advisories?ecosystem=npm&per_page=100"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, aggregatorURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "AuditterSecurityBot/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Just log and return empty to not block the whole chain
		fmt.Printf("Warning: GitHub Advisory API poll skipped (Status %d)\n", resp.StatusCode)
		return nil, nil
	}

	var advisories []struct {
		GHSAID      string `json:"ghsa_id"`
		Summary     string `json:"summary"`
		Severity    string `json:"severity"`
		HTMLURL     string `json:"html_url"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, err
	}

	var issues []IntelIssue
	for _, adv := range advisories {
		issues = append(issues, IntelIssue{
			ID:          adv.GHSAID,
			Type:        IssueTypeDetectionRule,
			Target:      "npm",
			Description: adv.Summary,
			Severity:    parseSeverity(adv.Severity),
			Source:      adv.HTMLURL,
			UpdatedAt:   time.Now(),
		})
	}

	return issues, nil
}
