package analyzer

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

type SuspiciousURLAnalyzer struct {
	ipRegex *regexp.Regexp
}

func NewSuspiciousURLAnalyzer() *SuspiciousURLAnalyzer {
	return &SuspiciousURLAnalyzer{
		ipRegex: regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
	}
}

func (a *SuspiciousURLAnalyzer) Name() string {
	return "suspicious-urls"
}

func (a *SuspiciousURLAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	return nil, nil
}

func (a *SuspiciousURLAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	// Simple extraction of things that look like URLs
	urlRegex := regexp.MustCompile(`https?://[^\s'"]+`)
	matches := urlRegex.FindAllString(content, -1)

	for _, match := range matches {
		u, err := url.Parse(match)
		if err != nil {
			continue
		}

		host := u.Hostname()
		if host == "" {
			continue
		}

		// Check for IP-based host (excluding localhost already handled by network analyzer)
		if a.ipRegex.MatchString(host) && host != "127.0.0.1" {
			findings = append(findings, Finding{
				Analyzer:       a.Name(),
				Title:          "Suspicious URL/Domain detected",
				Description:    "The package contains an IP-based URL (" + match + ") in " + filename + ", which is often used for C2 servers or to bypass DNS-based security.",
				Severity:       SeverityHigh,
				ExploitExample: "// C2 server connection\nfetch('" + match + "/payload');",
				Remediation:    "Use domains instead of IP addresses. Audit the owner of the destination IP.",
			})
			continue
		}

		// Entropy check for DGA (Domain Generation Algorithm)
		// We only check the domain part before the TLD
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			domain := parts[0]
			// If it's a long, highly random string
			if len(domain) > 15 && shannonEntropy([]byte(domain)) > 3.95 {
				findings = append(findings, Finding{
					Analyzer:       a.Name(),
					Title:          "Suspicious URL/Domain detected",
					Description:    "The package contains a highly randomized domain name (" + host + ") in " + filename + ", which may be a DGA domain used by malware.",
					Severity:       SeverityHigh,
					ExploitExample: "// DGA C2 domain\nfetch('https://" + host + "/ping');",
					Remediation:    "Verify if the domain belongs to a legitimate service. DGA domains are often used to evade domain-based blocking.",
				})
			}
		}
	}

	return findings
}
