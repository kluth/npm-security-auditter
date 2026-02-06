package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// StarjackingAnalyzer detects star-jacking attacks where malicious packages
// point their repository field to a popular, unrelated GitHub repo to
// appear legitimate and inherit its star count.
type StarjackingAnalyzer struct {
	httpClient *http.Client
}

func NewStarjackingAnalyzer() *StarjackingAnalyzer {
	return &StarjackingAnalyzer{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *StarjackingAnalyzer) Name() string {
	return "starjacking"
}

type githubRepoInfo struct {
	FullName   string    `json:"full_name"`
	CreatedAt  time.Time `json:"created_at"`
	Stars      int       `json:"stargazers_count"`
	Forks      int       `json:"forks_count"`
	Archived   bool      `json:"archived"`
	Fork       bool      `json:"fork"`
}

func (a *StarjackingAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	repo := version.Repository
	if repo == nil {
		repo = pkg.Repository
	}
	if repo == nil || repo.URL == "" {
		return nil, nil
	}

	owner, repoName := parseGitHubURL(repo.URL)
	if owner == "" || repoName == "" {
		return nil, nil
	}

	// Fetch repo info
	repoInfo, err := a.fetchRepoInfo(ctx, owner, repoName)
	if err != nil {
		return nil, nil // Non-fatal
	}

	// Get package creation time
	pkgCreated, ok := pkg.Time["created"]
	if !ok {
		return nil, nil
	}

	return a.analyzeStarjacking(
		pkg.Name,
		pkgCreated,
		repoInfo.CreatedAt,
		repoInfo.Stars,
		repoInfo.Forks,
		repoInfo.FullName,
	), nil
}

func (a *StarjackingAnalyzer) fetchRepoInfo(ctx context.Context, owner, repo string) (*githubRepoInfo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var info githubRepoInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (a *StarjackingAnalyzer) analyzeStarjacking(
	pkgName string,
	pkgCreated time.Time,
	repoCreated time.Time,
	stars int,
	forks int,
	repoFullName string,
) []Finding {
	var findings []Finding

	// Extract repo name for comparison
	parts := strings.Split(repoFullName, "/")
	repoShortName := ""
	if len(parts) >= 2 {
		repoShortName = parts[1]
	}

	// 1. Package is much newer than the repo it points to, and repo has many stars
	pkgAge := time.Since(pkgCreated)
	repoAge := time.Since(repoCreated)

	if pkgAge < 30*24*time.Hour && repoAge > 365*24*time.Hour && stars > 1000 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Star-jacking: new package points to established popular repo",
			Description: fmt.Sprintf("Package %q was created %d days ago but points to repo %q (created %d days ago, %d stars). This is a strong indicator of star-jacking.", pkgName, int(pkgAge.Hours()/24), repoFullName, int(repoAge.Hours()/24), stars),
			Severity:    SeverityCritical,
			ExploitExample: "Star-jacking inflates trust metrics:\n" +
				"    1. Attacker publishes malicious package on npm\n" +
				"    2. Sets repository field to a popular GitHub repo\n" +
				"    3. npm and security tools show the popular repo's stars\n" +
				"    4. Users trust the package based on fabricated popularity\n" +
				"    npm does NOT verify that the repo field is accurate",
			Remediation: "Verify the package is actually maintained by the repository owners. Check GitHub for references to this npm package.",
		})
	} else if pkgAge < 90*24*time.Hour && repoAge > 365*24*time.Hour && stars > 500 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Star-jacking: recent package with popular repository",
			Description: fmt.Sprintf("Package %q (age: %d days) points to popular repo %q (%d stars, age: %d days).", pkgName, int(pkgAge.Hours()/24), repoFullName, stars, int(repoAge.Hours()/24)),
			Severity:    SeverityHigh,
			ExploitExample: "Star-jacking exploits the trust associated with popular repos:\n" +
				"    - New package appears to have thousands of stars\n" +
				"    - Users and tools assume high popularity = safe\n" +
				"    - The actual package code may be completely unrelated",
			Remediation: "Check if the npm package is mentioned in the GitHub repo's README or package.json.",
		})
	}

	// 2. Package name doesn't match repo name
	normalizedPkg := strings.ToLower(strings.ReplaceAll(pkgName, "-", ""))
	normalizedRepo := strings.ToLower(strings.ReplaceAll(repoShortName, "-", ""))

	if repoShortName != "" && normalizedPkg != normalizedRepo {
		// Check if pkg name is at least partially in repo name or vice versa
		if !strings.Contains(normalizedRepo, normalizedPkg) && !strings.Contains(normalizedPkg, normalizedRepo) {
			// Only flag if repo has significant stars (otherwise it's normal for small projects)
			if stars > 100 {
				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       fmt.Sprintf("Star-jacking: name mismatch (npm: %s, repo: %s)", pkgName, repoFullName),
					Description: fmt.Sprintf("Package name %q does not match repository name %q. With %d stars on the repo, this may indicate star-jacking.", pkgName, repoFullName, stars),
					Severity:    SeverityMedium,
					ExploitExample: "Name mismatches between npm and GitHub suggest:\n" +
						"    - The package may be borrowing credibility from an unrelated repo\n" +
						"    - The repository field may have been set intentionally to deceive",
					Remediation: "Verify the relationship between the npm package and the GitHub repository.",
				})
			}
		}
	}

	return findings
}
