package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/matthias/auditter/internal/registry"
)

const osvAPIURL = "https://api.osv.dev/v1/query"

// VulnAnalyzer checks for known vulnerabilities via the OSV API.
type VulnAnalyzer struct {
	httpClient *http.Client
	osvURL     string
}

// NewVulnAnalyzer creates a new vulnerability analyzer.
func NewVulnAnalyzer() *VulnAnalyzer {
	return &VulnAnalyzer{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		osvURL:     osvAPIURL,
	}
}

func (v *VulnAnalyzer) Name() string { return "vulnerabilities" }

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity,omitempty"`
	Details  string        `json:"details"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func (v *VulnAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	query := osvQuery{
		Package: osvPackage{
			Name:      pkg.Name,
			Ecosystem: "npm",
		},
		Version: version.Version,
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("marshaling OSV query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.osvURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying OSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}

	var findings []Finding
	for _, vuln := range osvResp.Vulns {
		sev := classifyOSVSeverity(vuln)
		desc := vuln.Summary
		if desc == "" {
			desc = vuln.Details
		}
		if len(desc) > 200 {
			desc = desc[:200] + "..."
		}
		exploit := fmt.Sprintf(
			"This known vulnerability (%s) has a public advisory.\n"+
				"    Attackers actively scan for packages with known CVEs using automated tools.\n"+
				"    Search for proof-of-concept exploits:\n"+
				"      $ curl https://api.osv.dev/v1/vulns/%s\n"+
				"      $ open https://osv.dev/vulnerability/%s\n"+
				"    If this is a prototype pollution, RCE, or injection flaw, working\n"+
				"    exploits are likely already circulating in the wild.",
			vuln.ID, vuln.ID, vuln.ID)

		findings = append(findings, Finding{
			Analyzer:       v.Name(),
			Title:          fmt.Sprintf("Known vulnerability: %s", vuln.ID),
			Description:    desc,
			Severity:       sev,
			ExploitExample: exploit,
			Remediation:    fmt.Sprintf("Upgrade to a patched version if available. Check 'npm view %s versions' for newer releases. If no patch is available, assess if the vulnerable functionality is used in your project or consider switching to an alternative package.", pkg.Name),
		})
	}

	return findings, nil
}

func classifyOSVSeverity(vuln osvVuln) Severity {
	for _, s := range vuln.Severity {
		if s.Type == "CVSS_V3" {
			return cvssToSeverity(s.Score)
		}
	}
	return SeverityMedium
}

func cvssToSeverity(score string) Severity {
	// CVSS vector strings start with "CVSS:3.x/..." but the score field
	// in OSV is a numeric string or a vector. We check the first numeric part.
	// For simplicity, if we can't parse, default to medium.
	// In OSV, severity.score is typically a CVSS vector string like "CVSS:3.1/AV:N/AC:L/..."
	// We'll treat it as high if it contains "AC:L" and "AV:N" (network, low complexity)
	if len(score) == 0 {
		return SeverityMedium
	}

	// Simple heuristic based on common CVSS patterns
	// Use /X: prefix to avoid substring false positives (e.g., AC:H matching C:H)
	hasNetwork := bytes.Contains([]byte(score), []byte("AV:N"))
	hasLowComplexity := bytes.Contains([]byte(score), []byte("AC:L"))
	hasHighImpact := bytes.Contains([]byte(score), []byte("/C:H")) || bytes.Contains([]byte(score), []byte("/I:H"))

	if hasNetwork && hasLowComplexity && hasHighImpact {
		return SeverityCritical
	}
	if hasNetwork && hasHighImpact {
		return SeverityHigh
	}
	if hasNetwork {
		return SeverityMedium
	}
	return SeverityLow
}
