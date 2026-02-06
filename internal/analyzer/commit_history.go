package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// CommitHistoryAnalyzer checks GitHub commit history for suspicious patterns.
type CommitHistoryAnalyzer struct {
	httpClient *http.Client
	token      string // GitHub token (optional)
}

func NewCommitHistoryAnalyzer() *CommitHistoryAnalyzer {
	return &CommitHistoryAnalyzer{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *CommitHistoryAnalyzer) Name() string {
	return "commit-history"
}

// SetToken allows setting a GitHub token for authenticated requests.
func (a *CommitHistoryAnalyzer) SetToken(token string) {
	a.token = token
}

// GitHub API response structures.
type githubCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Name  string    `json:"name"`
			Email string    `json:"email"`
			Date  time.Time `json:"date"`
		} `json:"author"`
		Committer struct {
			Name  string    `json:"name"`
			Email string    `json:"email"`
			Date  time.Time `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
	Author struct {
		Login string `json:"login"`
	} `json:"author"`
	Stats struct {
		Additions int `json:"additions"`
		Deletions int `json:"deletions"`
	} `json:"stats"`
}

type githubContributor struct {
	Login         string `json:"login"`
	Contributions int    `json:"contributions"`
}

func (a *CommitHistoryAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	// Get repository URL
	repo := version.Repository
	if repo == nil {
		repo = pkg.Repository
	}
	if repo == nil || repo.URL == "" {
		return nil, nil // No repository to analyze
	}

	owner, repoName := parseGitHubURL(repo.URL)
	if owner == "" || repoName == "" {
		return nil, nil // Not a GitHub repository
	}

	// Fetch recent commits
	commits, err := a.fetchRecentCommits(ctx, owner, repoName)
	if err != nil {
		// Non-fatal - might be rate limited or private repo
		return nil, nil
	}

	// Analyze commit patterns
	findings = append(findings, a.analyzeCommitPatterns(commits)...)

	// Fetch contributors
	contributors, err := a.fetchContributors(ctx, owner, repoName)
	if err == nil {
		findings = append(findings, a.analyzeContributors(contributors)...)
	}

	return findings, nil
}

func (a *CommitHistoryAnalyzer) fetchRecentCommits(ctx context.Context, owner, repo string) ([]githubCommit, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?per_page=30", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if a.token != "" {
		req.Header.Set("Authorization", "token "+a.token)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var commits []githubCommit
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return nil, err
	}

	return commits, nil
}

func (a *CommitHistoryAnalyzer) fetchContributors(ctx context.Context, owner, repo string) ([]githubContributor, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contributors?per_page=10", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if a.token != "" {
		req.Header.Set("Authorization", "token "+a.token)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var contributors []githubContributor
	if err := json.NewDecoder(resp.Body).Decode(&contributors); err != nil {
		return nil, err
	}

	return contributors, nil
}

func (a *CommitHistoryAnalyzer) analyzeCommitPatterns(commits []githubCommit) []Finding {
	var findings []Finding

	if len(commits) == 0 {
		return findings
	}

	// Track suspicious patterns
	var (
		recentBurstCount     int
		suspiciousMessages   []string
		newContributorCommit *githubCommit
		largeCommits         []string
	)

	now := time.Now()
	oneWeekAgo := now.AddDate(0, 0, -7)
	oneHourAgo := now.Add(-time.Hour)

	// Get the typical author
	authorCounts := make(map[string]int)
	for _, c := range commits {
		if c.Author.Login != "" {
			authorCounts[c.Author.Login]++
		}
	}

	// Find the primary author
	var primaryAuthor string
	maxCount := 0
	for author, count := range authorCounts {
		if count > maxCount {
			maxCount = count
			primaryAuthor = author
		}
	}

	// Analyze each commit
	for i := range commits {
		c := &commits[i]
		commitTime := c.Commit.Author.Date

		// Check for recent burst of activity
		if commitTime.After(oneHourAgo) {
			recentBurstCount++
		}

		// Check for suspicious commit messages
		msgLower := strings.ToLower(c.Commit.Message)
		if isSuspiciousCommitMessage(msgLower) {
			suspiciousMessages = append(suspiciousMessages, c.Commit.Message)
		}

		// Check for new contributor making changes
		if c.Author.Login != "" && c.Author.Login != primaryAuthor {
			if authorCounts[c.Author.Login] == 1 && commitTime.After(oneWeekAgo) {
				newContributorCommit = c
			}
		}

		// Check for unusually large changes (if stats available)
		if c.Stats.Additions > 1000 || c.Stats.Deletions > 500 {
			largeCommits = append(largeCommits, c.SHA[:7])
		}
	}

	// Report burst of recent activity
	if recentBurstCount > 5 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Burst of recent commits",
			Description: fmt.Sprintf("%d commits in the last hour - unusual activity pattern", recentBurstCount),
			Severity:    SeverityMedium,
			ExploitExample: "Rapid commits before a release can indicate:\n" +
				"    - Last-minute malicious code injection\n" +
				"    - Attempt to push changes before review\n" +
				"    - Compromised CI/CD pushing automated changes",
			Remediation: "Review all recent commits carefully before using this version.",
		})
	}

	// Report suspicious commit messages
	if len(suspiciousMessages) > 0 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Suspicious commit messages",
			Description: fmt.Sprintf("Found %d commits with suspicious messages: %s", len(suspiciousMessages), strings.Join(suspiciousMessages[:minInt(3, len(suspiciousMessages))], "; ")),
			Severity:    SeverityMedium,
			ExploitExample: "Attackers sometimes leave obvious traces:\n" +
				"    - 'test' or 'fix' for malicious changes\n" +
				"    - Empty or meaningless messages\n" +
				"    - Messages that don't match the actual changes",
			Remediation: "Compare commit messages with actual code changes.",
		})
	}

	// Report new contributor
	if newContributorCommit != nil {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Recent commit from new contributor",
			Description: fmt.Sprintf("User %q made their first commit recently (%s)", newContributorCommit.Author.Login, newContributorCommit.Commit.Author.Date.Format("2006-01-02")),
			Severity:    SeverityMedium,
			ExploitExample: "New contributor pattern seen in event-stream attack:\n" +
				"    1. Attacker offers to 'help maintain' dormant package\n" +
				"    2. Gets commit access through social engineering\n" +
				"    3. Injects malicious code in subsequent commits",
			Remediation: "Verify the new contributor's identity and review their changes carefully.",
		})
	}

	// Report large changes
	if len(largeCommits) > 0 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Unusually large code changes",
			Description: fmt.Sprintf("Commits with large diffs: %s", strings.Join(largeCommits, ", ")),
			Severity:    SeverityLow,
			ExploitExample: "Large commits can hide malicious code:\n" +
				"    - Attacker buries payload in thousands of lines\n" +
				"    - Reviewers may skip detailed review of large diffs\n" +
				"    - Obfuscated code is hard to spot in bulk changes",
			Remediation: "Review large commits line by line, paying attention to any network, eval, or process code.",
		})
	}

	return findings
}

func (a *CommitHistoryAnalyzer) analyzeContributors(contributors []githubContributor) []Finding {
	var findings []Finding

	if len(contributors) == 0 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No contributors found",
			Description: "Repository has no public contributor information",
			Severity:    SeverityLow,
			ExploitExample: "Private or hidden contributor lists prevent community verification:\n" +
				"    - Cannot assess who has commit access\n" +
				"    - Cannot verify maintainer identity",
			Remediation: "Manually verify the repository ownership and contributor list.",
		})
		return findings
	}

	// Check if a single contributor dominates
	if len(contributors) >= 2 {
		totalContributions := 0
		for _, c := range contributors {
			totalContributions += c.Contributions
		}

		topContributor := contributors[0]
		topRatio := float64(topContributor.Contributions) / float64(totalContributions)

		if topRatio > 0.95 && totalContributions > 10 {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Single contributor dominance",
				Description: fmt.Sprintf("User %q has %.0f%% of all contributions", topContributor.Login, topRatio*100),
				Severity:    SeverityLow,
				ExploitExample: "Single-contributor projects have higher takeover risk:\n" +
					"    - If the account is compromised, there's no oversight\n" +
					"    - No code review from other maintainers\n" +
					"    - Changes go directly to production",
				Remediation: "Consider the bus factor risk. Pin to specific versions and audit updates carefully.",
			})
		}
	}

	return findings
}

// isSuspiciousCommitMessage checks for commit messages that might indicate malicious changes.
func isSuspiciousCommitMessage(msg string) bool {
	// Very short or empty messages
	if len(strings.TrimSpace(msg)) < 3 {
		return true
	}

	// Generic messages often used to hide malicious changes
	suspiciousPatterns := []string{
		"^(test|testing|fix|fixed|update|updated|patch|minor|small)$",
		"^(wip|tmp|temp|asdf|qwer|todo)$",
		"^\\.$",
		"^\\.\\.\\.$",
		"^-+$",
		"^_+$",
		"^x+$",
		"initial commit", // On an established repo
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString("(?i)"+pattern, msg); matched {
			return true
		}
	}

	return false
}

// parseGitHubURL extracts owner and repo name from a GitHub URL.
func parseGitHubURL(url string) (owner, repo string) {
	url = strings.ToLower(url)
	url = strings.TrimPrefix(url, "git+")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "github.com/")
	url = strings.TrimPrefix(url, "www.github.com/")
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")

	parts := strings.Split(url, "/")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "", ""
}
