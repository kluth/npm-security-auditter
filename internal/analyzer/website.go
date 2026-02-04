package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// RepoVerifierAnalyzer verifies the source repository and homepage of a package.
type RepoVerifierAnalyzer struct {
	httpClient *http.Client
}

func NewRepoVerifierAnalyzer() *RepoVerifierAnalyzer {
	return &RepoVerifierAnalyzer{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *RepoVerifierAnalyzer) Name() string {
	return "repo-verification"
}

func (a *RepoVerifierAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	// Determine repo URL from package or version metadata.
	repoURL := ""
	if pkg.Repository != nil && pkg.Repository.URL != "" {
		repoURL = pkg.Repository.URL
	} else if version.Repository != nil && version.Repository.URL != "" {
		repoURL = version.Repository.URL
	}

	if repoURL != "" {
		owner, repo, platform := parseRepoURL(repoURL)
		if owner == "" || repo == "" {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Unparseable repository URL",
				Description: fmt.Sprintf("Could not parse repository URL %q to extract owner and repo.", repoURL),
				Severity:    SeverityLow,
			})
		} else if platform == "github" {
			ghFindings := a.verifyGitHub(ctx, owner, repo, pkg, version)
			findings = append(findings, ghFindings...)
		}
	}

	// Homepage check.
	homepage := version.Homepage
	if homepage == "" && pkg.Repository != nil {
		// No separate homepage; skip this check.
	} else if homepage != "" {
		hpFindings := a.checkHomepage(ctx, homepage)
		findings = append(findings, hpFindings...)
	}

	return findings, nil
}

// parseRepoURL extracts owner, repo, and platform from various git URL formats.
func parseRepoURL(url string) (owner, repo, platform string) {
	// Normalize: strip git+, git://, ssh://
	url = strings.TrimPrefix(url, "git+")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimPrefix(url, "ssh://")
	url = strings.TrimSuffix(url, ".git")

	// Handle git@github.com:owner/repo
	if strings.HasPrefix(url, "git@") {
		parts := strings.SplitN(url, ":", 2)
		if len(parts) == 2 {
			host := strings.TrimPrefix(parts[0], "git@")
			platform = hostToPlatform(host)
			ownerRepo := strings.TrimPrefix(parts[1], "/")
			segs := strings.SplitN(ownerRepo, "/", 2)
			if len(segs) == 2 {
				return segs[0], segs[1], platform
			}
		}
		return "", "", ""
	}

	// Handle https://github.com/owner/repo
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	parts := strings.SplitN(url, "/", 4)
	if len(parts) >= 3 {
		platform = hostToPlatform(parts[0])
		return parts[1], parts[2], platform
	}

	return "", "", ""
}

func hostToPlatform(host string) string {
	switch {
	case strings.Contains(host, "github.com"):
		return "github"
	case strings.Contains(host, "gitlab.com"):
		return "gitlab"
	case strings.Contains(host, "bitbucket.org"):
		return "bitbucket"
	default:
		return "unknown"
	}
}

// ghRepoResponse is a minimal GitHub API repos response.
type ghRepoResponse struct {
	FullName    string    `json:"full_name"`
	Description string    `json:"description"`
	Archived    bool      `json:"archived"`
	Disabled    bool      `json:"disabled"`
	PushedAt    time.Time `json:"pushed_at"`
	Stars       int       `json:"stargazers_count"`
	Forks       int       `json:"forks_count"`
}

func (a *RepoVerifierAnalyzer) verifyGitHub(ctx context.Context, owner, repo string, pkg *registry.PackageMetadata, version *registry.PackageVersion) []Finding {
	var findings []Finding

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		findings = append(findings, Finding{
			Analyzer:    "repo-verification",
			Title:       "GitHub API request failed",
			Description: fmt.Sprintf("Failed to verify repository %s/%s: %s", owner, repo, err.Error()),
			Severity:    SeverityLow,
		})
		return findings
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		findings = append(findings, Finding{
			Analyzer:    "repo-verification",
			Title:       "Repository not found",
			Description: fmt.Sprintf("GitHub repository %s/%s does not exist (404). The source code is unavailable.", owner, repo),
			Severity:    SeverityCritical,
		})
		return findings

	case http.StatusForbidden, http.StatusTooManyRequests:
		findings = append(findings, Finding{
			Analyzer:    "repo-verification",
			Title:       "GitHub API rate limited",
			Description: "GitHub API rate limit reached. Repository verification was skipped.",
			Severity:    SeverityLow,
		})
		return findings
	}

	if resp.StatusCode != http.StatusOK {
		return findings
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return findings
	}

	var ghRepo ghRepoResponse
	if err := json.Unmarshal(body, &ghRepo); err != nil {
		return findings
	}

	// Archived check.
	if ghRepo.Archived {
		findings = append(findings, Finding{
			Analyzer:    "repo-verification",
			Title:       "Repository is archived",
			Description: fmt.Sprintf("GitHub repository %s/%s is archived. The package may be unmaintained.", owner, repo),
			Severity:    SeverityMedium,
		})
	}

	// Disabled check.
	if ghRepo.Disabled {
		findings = append(findings, Finding{
			Analyzer:    "repo-verification",
			Title:       "Repository is disabled",
			Description: fmt.Sprintf("GitHub repository %s/%s is disabled by GitHub, possibly due to policy violations.", owner, repo),
			Severity:    SeverityHigh,
		})
	}

	// Stale repo: no push in >1 year.
	if !ghRepo.PushedAt.IsZero() && time.Since(ghRepo.PushedAt) > 365*24*time.Hour {
		findings = append(findings, Finding{
			Analyzer:    "repo-verification",
			Title:       "Repository appears abandoned",
			Description: fmt.Sprintf("Last push to %s/%s was %s. The package may be unmaintained.", owner, repo, ghRepo.PushedAt.Format("2006-01-02")),
			Severity:    SeverityLow,
		})
	}

	// Description similarity.
	if pkg.Description != "" && ghRepo.Description != "" {
		similarity := jaccardWordSimilarity(pkg.Description, ghRepo.Description)
		if similarity < 0.3 {
			findings = append(findings, Finding{
				Analyzer:    "repo-verification",
				Title:       "Description mismatch between npm and GitHub",
				Description: fmt.Sprintf("npm description and GitHub repo description have low similarity (%.2f). This may indicate the package points to a wrong or hijacked repository.", similarity),
				Severity:    SeverityMedium,
			})
		}
	}

	// README comparison.
	readmeFindings := a.compareReadme(ctx, owner, repo, pkg.Readme)
	findings = append(findings, readmeFindings...)

	return findings
}

func (a *RepoVerifierAnalyzer) compareReadme(ctx context.Context, owner, repo, npmReadme string) []Finding {
	if npmReadme == "" {
		return nil
	}

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/readme", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github.v3.raw")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	ghReadme := string(body)
	similarity := jaccardWordSimilarity(npmReadme, ghReadme)
	if similarity < 0.3 {
		return []Finding{{
			Analyzer:    "repo-verification",
			Title:       "README mismatch between npm and GitHub",
			Description: fmt.Sprintf("npm README and GitHub README have low similarity (%.2f). The package may have been compromised or the repo link is incorrect.", similarity),
			Severity:    SeverityMedium,
		}}
	}

	return nil
}

func (a *RepoVerifierAnalyzer) checkHomepage(ctx context.Context, homepage string) []Finding {
	if !strings.HasPrefix(homepage, "http://") && !strings.HasPrefix(homepage, "https://") {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, homepage, nil)
	if err != nil {
		return nil
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return []Finding{{
			Analyzer:    "repo-verification",
			Title:       "Homepage unreachable",
			Description: fmt.Sprintf("Homepage %s could not be reached: %s", homepage, err.Error()),
			Severity:    SeverityLow,
		}}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []Finding{{
			Analyzer:    "repo-verification",
			Title:       "Homepage returns 404",
			Description: fmt.Sprintf("Homepage %s returns HTTP 404. The project page may have been removed.", homepage),
			Severity:    SeverityMedium,
		}}
	}

	return nil
}

// jaccardWordSimilarity computes the Jaccard similarity between two texts
// based on their word sets.
func jaccardWordSimilarity(a, b string) float64 {
	wordsA := wordSet(a)
	wordsB := wordSet(b)

	if len(wordsA) == 0 && len(wordsB) == 0 {
		return 1.0
	}

	intersection := 0
	for w := range wordsA {
		if wordsB[w] {
			intersection++
		}
	}

	union := len(wordsA)
	for w := range wordsB {
		if !wordsA[w] {
			union++
		}
	}

	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

var wordSplitter = regexp.MustCompile(`\W+`)

func wordSet(text string) map[string]bool {
	words := wordSplitter.Split(strings.ToLower(text), -1)
	set := make(map[string]bool, len(words))
	for _, w := range words {
		if len(w) > 1 { // skip single-char tokens
			set[w] = true
		}
	}
	return set
}

