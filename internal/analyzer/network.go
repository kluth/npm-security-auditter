package analyzer

import (
	"context"
	"fmt"
	"regexp"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

type netPattern struct {
	pattern  *regexp.Regexp
	severity Severity
	name     string
}

var (
	networkPatterns = []netPattern{
		{regexp.MustCompile(`169\.254\.169\.254`), SeverityCritical, "Cloud Metadata Service"},
		{regexp.MustCompile(`localhost|127\.0\.0\.1|::1`), SeverityHigh, "Localhost"},
		{regexp.MustCompile(`10\.\d{1,3}\.\d{1,3}\.\d{1,3}`), SeverityHigh, "Private Network (10.x.x.x)"},
		{regexp.MustCompile(`192\.168\.\d{1,3}\.\d{1,3}`), SeverityHigh, "Private Network (192.168.x.x)"},
		{regexp.MustCompile(`172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}`), SeverityHigh, "Private Network (172.16.x.x)"},
	}
)

type PrivateNetworkAnalyzer struct{}

func NewPrivateNetworkAnalyzer() *PrivateNetworkAnalyzer {
	return &PrivateNetworkAnalyzer{}
}

func (a *PrivateNetworkAnalyzer) Name() string {
	return "network-security"
}

func (a *PrivateNetworkAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	return nil, nil
}

func (a *PrivateNetworkAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, p := range networkPatterns {
		if p.pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Private network access detected",
				Description: "The package contains references to " + p.name + " in " + filename + ". This may indicate attempts to scan internal networks or steal cloud credentials.",
				Severity:    p.severity,
				ExploitExample: fmt.Sprintf("fetch('http://%s/latest/meta-data/iam/security-credentials/');", p.pattern.String()),
				Remediation:    "Block access to the cloud metadata service (169.254.169.254) from within your application environment. Ensure no internal IPs are leaked.",
			})
			break // Highest severity first
		}
	}

	return findings
}
