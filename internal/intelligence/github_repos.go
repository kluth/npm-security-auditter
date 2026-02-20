package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kluth/npm-security-auditter/internal/project"
)

// GitHubRepo represents a repository found on GitHub.
type GitHubRepo struct {
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	Stars       int    `json:"stargazers_count"`
	URL         string `json:"html_url"`
}

// GitHubSearchResponse is the response from the GitHub Search API.
type GitHubSearchResponse struct {
	TotalCount int          `json:"total_count"`
	Items      []GitHubRepo `json:"items"`
}

// FetchTopReposByCategory searches GitHub for top repos in a given category/topic.
func FetchTopReposByCategory(ctx context.Context, category string, limit int) ([]project.Dependency, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	// We search for repositories with the given topic, in JavaScript/TypeScript, sorted by stars.
	// We assume the repo name corresponds to the npm package name, which is often true for top repos.
	query := fmt.Sprintf("topic:%s language:javascript language:typescript", category)
	searchURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&per_page=%d", url.QueryEscape(query), limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "AuditterSecurityBot/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API error: status %d", resp.StatusCode)
	}

	var searchResp GitHubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}

	var deps []project.Dependency
	for _, repo := range searchResp.Items {
		// Try to extract package name. Usually it's the repo name.
		// For scoped packages or repos containing multiple packages, this might be tricky,
		// but for "top repos" it's a good heuristic.
		name := repo.Name
		// Special cases or cleaning could be added here
		deps = append(deps, project.Dependency{Name: name})
	}

	return deps, nil
}

// GetDefaultCategories returns a list of recommended categories for auditing.
func GetDefaultCategories() []string {
	return []string{
		"web-framework",
		"testing",
		"utility",
		"state-management",
		"cli",
		"backend",
		"database",
		"authentication",
		"monitoring",
		"security",
	}
}
