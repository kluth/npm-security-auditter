package analyzer

import (
	"context"
	"regexp"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

type telPattern struct {
	pattern  *regexp.Regexp
	severity Severity
}

var (
	telemetryPatterns = []telPattern{
		{regexp.MustCompile(`(google-analytics\.com|segment\.io|mixpanel\.com|intercom\.io|posthog\.com|sentry\.io|amplitude\.com)`), SeverityMedium},
		{regexp.MustCompile(`(@segment/|@sentry/|mixpanel-browser|ga-lib)`), SeverityMedium},
		{regexp.MustCompile(`(?i)(telemetry|analytics|track)\.(track|send|capture|event)`), SeverityLow},
	}
)

type TelemetryAnalyzer struct{}

func NewTelemetryAnalyzer() *TelemetryAnalyzer {
	return &TelemetryAnalyzer{}
}

func (a *TelemetryAnalyzer) Name() string {
	return "telemetry"
}

func (a *TelemetryAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	return nil, nil
}

func (a *TelemetryAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, p := range telemetryPatterns {
		if p.pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Telemetry/Analytics detected",
				Description: "The package contains code or URLs associated with telemetry or analytics tracking in " + filename,
				Severity:    p.severity,
				ExploitExample: "// Example of data collection\nanalytics.track('install_event', { user: os.userInfo() });",
				Remediation:    "Review if this telemetry is documented and if it can be disabled. For sensitive environments, block these domains at the network level.",
			})
			break // One finding per file is enough, take the highest severity
		}
	}

	return findings
}
