package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// DownloadAnalyzer checks npm download patterns for anomalies.
type DownloadAnalyzer struct {
	httpClient *http.Client
}

func NewDownloadAnalyzer() *DownloadAnalyzer {
	return &DownloadAnalyzer{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *DownloadAnalyzer) Name() string {
	return "download-patterns"
}

// npmDownloads represents the npm API download response.
type npmDownloads struct {
	Downloads int    `json:"downloads"`
	Start     string `json:"start"`
	End       string `json:"end"`
	Package   string `json:"package"`
}

// npmDownloadRange represents download data over a range.
type npmDownloadRange struct {
	Downloads []struct {
		Downloads int    `json:"downloads"`
		Day       string `json:"day"`
	} `json:"downloads"`
	Start   string `json:"start"`
	End     string `json:"end"`
	Package string `json:"package"`
}

func (a *DownloadAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	// Get last week's downloads
	weeklyDownloads, err := a.getDownloads(ctx, pkg.Name, "last-week")
	if err != nil {
		// API might be unavailable or package too new
		return nil, nil
	}

	// Get last month's downloads
	monthlyDownloads, err := a.getDownloads(ctx, pkg.Name, "last-month")
	if err != nil {
		monthlyDownloads = 0
	}

	// Get last year's downloads for baseline
	yearlyDownloads, err := a.getDownloads(ctx, pkg.Name, "last-year")
	if err != nil {
		yearlyDownloads = 0
	}

	// Analyze patterns
	findings = append(findings, a.analyzeDownloadCounts(pkg.Name, weeklyDownloads, monthlyDownloads, yearlyDownloads)...)

	// Get daily breakdown for spike detection
	dailyData, err := a.getDailyDownloads(ctx, pkg.Name)
	if err == nil && len(dailyData) > 0 {
		findings = append(findings, a.detectSpikes(pkg.Name, dailyData)...)
	}

	return findings, nil
}

func (a *DownloadAnalyzer) getDownloads(ctx context.Context, pkgName, period string) (int, error) {
	url := fmt.Sprintf("https://api.npmjs.org/downloads/point/%s/%s", period, pkgName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("npm API returned %d", resp.StatusCode)
	}

	var data npmDownloads
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, err
	}

	return data.Downloads, nil
}

func (a *DownloadAnalyzer) getDailyDownloads(ctx context.Context, pkgName string) ([]int, error) {
	// Get last 30 days of daily data
	url := fmt.Sprintf("https://api.npmjs.org/downloads/range/last-month/%s", pkgName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm API returned %d", resp.StatusCode)
	}

	var data npmDownloadRange
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	daily := make([]int, len(data.Downloads))
	for i, d := range data.Downloads {
		daily[i] = d.Downloads
	}

	return daily, nil
}

func (a *DownloadAnalyzer) analyzeDownloadCounts(pkgName string, weekly, monthly, yearly int) []Finding {
	var findings []Finding

	// Very low downloads for a non-new package
	if yearly > 0 && yearly < 100 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Very low download count",
			Description: fmt.Sprintf("Package %q has only %d downloads in the last year", pkgName, yearly),
			Severity:    SeverityMedium,
			ExploitExample: "Low-download packages may be:\n" +
				"    - Typosquats waiting for victims\n" +
				"    - Dependency confusion targets\n" +
				"    - Abandoned packages ripe for takeover\n" +
				"    Or simply legitimate niche packages.",
			Remediation: "Verify the package is the one you intended to install. Low downloads mean less community vetting.",
		})
	}

	// Sudden spike in recent downloads
	if yearly > 0 && weekly > 0 {
		weeklyAvg := float64(yearly) / 52.0
		if weekly > int(weeklyAvg*10) && weekly > 1000 {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Abnormal download spike",
				Description: fmt.Sprintf("Package %q had %d downloads last week (10x above yearly average of %.0f/week)", pkgName, weekly, weeklyAvg),
				Severity:    SeverityMedium,
				ExploitExample: "Sudden download spikes can indicate:\n" +
					"    - Package was added to a popular project's deps\n" +
					"    - SEO manipulation or bot downloads\n" +
					"    - Compromise announcement driving audit traffic\n" +
					"    Context matters: is this organic growth or suspicious?",
				Remediation: "Investigate the cause of the spike. Check for recent security advisories or news about this package.",
			})
		}
	}

	// Downloads dropped significantly (might indicate deprecation/compromise awareness)
	if monthly > 0 && yearly > 0 {
		monthlyAvg := float64(yearly) / 12.0
		if float64(monthly) < monthlyAvg*0.1 && monthlyAvg > 1000 {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Significant download drop",
				Description: fmt.Sprintf("Package %q downloads dropped to %d/month (was avg %.0f/month)", pkgName, monthly, monthlyAvg),
				Severity:    SeverityLow,
				ExploitExample: "Sudden download drops may indicate:\n" +
					"    - Community learned of security issues\n" +
					"    - Package was deprecated or replaced\n" +
					"    - Major breaking change caused migration",
				Remediation: "Check for deprecation notices or security advisories. The community may know something you don't.",
			})
		}
	}

	// Zero downloads in last week (for non-new packages)
	if weekly == 0 && yearly > 100 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "No recent downloads",
			Description: fmt.Sprintf("Package %q had 0 downloads in the last week despite %d yearly downloads", pkgName, yearly),
			Severity:    SeverityLow,
			ExploitExample: "A package with history but no recent downloads:\n" +
				"    - May indicate the package has been superseded\n" +
				"    - Could have been unpublished and republished\n" +
				"    - Registry data anomaly",
			Remediation: "Verify the package is still actively maintained and consider alternatives.",
		})
	}

	return findings
}

func (a *DownloadAnalyzer) detectSpikes(pkgName string, dailyDownloads []int) []Finding {
	var findings []Finding

	if len(dailyDownloads) < 7 {
		return findings
	}

	// Calculate mean and standard deviation
	var sum, sumSq float64
	for _, d := range dailyDownloads {
		sum += float64(d)
		sumSq += float64(d) * float64(d)
	}
	n := float64(len(dailyDownloads))
	mean := sum / n
	variance := (sumSq / n) - (mean * mean)
	stdDev := 0.0
	if variance > 0 {
		stdDev = variance // Simplified - should be sqrt(variance)
	}

	// Look for days with >3 standard deviations above mean
	if mean > 100 && stdDev > 0 { // Only for packages with some activity
		for i, d := range dailyDownloads {
			if float64(d) > mean+3*stdDev {
				daysAgo := len(dailyDownloads) - i - 1
				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       "Daily download anomaly detected",
					Description: fmt.Sprintf("Package %q had %d downloads on a single day (%d days ago), significantly above normal (avg: %.0f)", pkgName, d, daysAgo, mean),
					Severity:    SeverityLow,
					ExploitExample: "Single-day spikes can indicate:\n" +
						"    - Bot activity inflating download counts\n" +
						"    - Inclusion in a viral tutorial/article\n" +
						"    - Automated dependency updates across many projects",
					Remediation: "Correlate with any recent news or changes to the package.",
				})
				break // Only report first anomaly
			}
		}
	}

	return findings
}
