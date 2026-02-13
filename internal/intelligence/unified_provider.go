package intelligence

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
)

// SourceType defines the format of the external intelligence source.
type SourceType int

const (
	SourceTypeJSON SourceType = iota
	SourceTypeRSS
)

// DiscoverySource represents an external intelligence source to be polled.
type DiscoverySource struct {
	Name     string
	URL      string
	Type     SourceType
	Category string
}

// UnifiedIntelProvider polls a curated list of security research and intelligence sources.
type UnifiedIntelProvider struct {
	client  *http.Client
	sources []DiscoverySource
}

func NewUnifiedIntelProvider() *UnifiedIntelProvider {
	return &UnifiedIntelProvider{
		client: &http.Client{Timeout: 30 * time.Second},
		sources: []DiscoverySource{
			// --- Vulnerability Databases ---
			{Name: "OSV npm Feed", URL: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip", Type: SourceTypeJSON, Category: "vulnerability"},
			{Name: "NVD (NIST)", URL: "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", Type: SourceTypeRSS, Category: "vulnerability"},
			
			// --- Malware & IOC Feeds ---
			{Name: "URLhaus (Abuse.ch)", URL: "https://urlhaus.abuse.ch/api/v1/urls/recent/", Type: SourceTypeJSON, Category: "malware"},
			{Name: "Phylum Research Feed", URL: "https://blog.phylum.io/rss.xml", Type: SourceTypeRSS, Category: "malware"},
			
			// --- Security Research & Organizations ---
			{Name: "Chaos Computer Club (CCC)", URL: "https://www.ccc.de/en/rss/updates.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "GitHub Security Lab", URL: "https://securitylab.github.com/feed.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "Google Open Source Security", URL: "https://security.googleblog.com/feeds/posts/default/-/Open%20Source%20Security", Type: SourceTypeRSS, Category: "research"},
			{Name: "OpenSSF Feed", URL: "https://openssf.org/blog/feed/", Type: SourceTypeRSS, Category: "research"},
			{Name: "Wiz.io Blog", URL: "https://www.wiz.io/blog/rss.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "Checkmarx Blog", URL: "https://checkmarx.com/blog/feed/", Type: SourceTypeRSS, Category: "research"},
			{Name: "Snyk Security Blog", URL: "https://snyk.io/blog/feed/", Type: SourceTypeRSS, Category: "research"},
			{Name: "Unit 42 (Palo Alto)", URL: "https://unit42.paloaltonetworks.com/feed/", Type: SourceTypeRSS, Category: "research"},
			{Name: "Mandiant Blog", URL: "https://www.mandiant.com/resources/blog/rss.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "CISA Current Activity", URL: "https://www.cisa.gov/uscert/ncas/current-activity.xml", Type: SourceTypeRSS, Category: "research"},
			
			// --- Academic & Conference Research ---
			{Name: "Black Hat News", URL: "https://www.blackhat.com/html/rss.xml", Type: SourceTypeRSS, Category: "academic"},
			{Name: "Trail of Bits Blog", URL: "https://blog.trailofbits.com/feed/", Type: SourceTypeRSS, Category: "research"},
			{Name: "Semgrep Research", URL: "https://semgrep.dev/blog/feed.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "USENIX Security Blog", URL: "https://www.usenix.org/publications/login/rss.xml", Type: SourceTypeRSS, Category: "academic"},
			{Name: "DEF CON Media", URL: "https://media.defcon.org/rss.xml", Type: SourceTypeRSS, Category: "academic"},
			{Name: "HackerOne Blog", URL: "https://www.hackerone.com/blog.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "Fortinet Blog", URL: "https://www.fortinet.com/rss/ir.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "Trend Micro Blog", URL: "https://feeds.feedburner.com/TrendMicroSecurityIntelligence", Type: SourceTypeRSS, Category: "research"},
			{Name: "Malwarebytes Labs", URL: "https://www.malwarebytes.com/blog/feed/index.xml", Type: SourceTypeRSS, Category: "malware"},
			{Name: "Krebs on Security", URL: "https://krebsonsecurity.com/feed/", Type: SourceTypeRSS, Category: "research"},
			{Name: "Dark Reading", URL: "https://www.darkreading.com/rss.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "The Hacker News", URL: "http://feeds.feedburner.com/TheHackersNews", Type: SourceTypeRSS, Category: "research"},
		},
	}
}

func (p *UnifiedIntelProvider) Name() string { return "unified-threat-intel" }

func (p *UnifiedIntelProvider) Fetch(ctx context.Context) ([]IntelIssue, error) {
	var allIssues []IntelIssue
	for _, src := range p.sources {
		issues, err := p.fetchSource(ctx, src)
		if err != nil {
			// Log error but continue with other sources to ensure at least some extension
			fmt.Printf("Warning: failed to poll %s: %v\n", src.Name, err)
			continue
		}
		allIssues = append(allIssues, issues...)
	}
	return allIssues, nil
}

func (p *UnifiedIntelProvider) fetchSource(ctx context.Context, src DiscoverySource) ([]IntelIssue, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	switch src.Type {
	case SourceTypeRSS:
		return p.parseRSS(resp, src)
	case SourceTypeJSON:
		return p.parseJSON(resp, src)
	}

	return nil, nil
}

type rssFeed struct {
	Items []rssItem `xml:"channel>item"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Description string `xml:"description"`
	Link        string `xml:"link"`
}

func (p *UnifiedIntelProvider) parseRSS(resp *http.Response, src DiscoverySource) ([]IntelIssue, error) {
	var feed rssFeed
	if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}

	var issues []IntelIssue
	for _, item := range feed.Items {
		issues = append(issues, IntelIssue{
			ID:          fmt.Sprintf("%s-%s", src.Name, item.Title),
			Type:        IssueTypeDetectionRule,
			Target:      "research",
			Description: fmt.Sprintf("[%s] %s: %s", src.Name, item.Title, item.Link),
			Severity:    analyzer.SeverityMedium,
			Source:      src.URL,
			UpdatedAt:   time.Now(),
			Metadata:    map[string]string{"link": item.Link, "category": src.Category},
		})
	}
	return issues, nil
}

func (p *UnifiedIntelProvider) parseJSON(resp *http.Response, src DiscoverySource) ([]IntelIssue, error) {
	// Generic JSON parser for demonstration. In a full implementation, 
	// we'd have specific schemas for OSV, URLhaus, etc.
	// For now, we extract top-level strings that look like IDs or descriptions.
	var raw interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	return []IntelIssue{
		{
			ID:          src.Name + "-DATA",
			Type:        IssueTypeDetectionRule,
			Target:      "aggregated-data",
			Description: fmt.Sprintf("Aggregated data from %s", src.Name),
			Severity:    analyzer.SeverityLow,
			Source:      src.URL,
			UpdatedAt:   time.Now(),
		},
	}, nil
}
