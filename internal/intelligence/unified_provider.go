package intelligence

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
)

// SourceType defines the format of the external intelligence source.
type SourceType int

const (
	SourceTypeJSON SourceType = iota
	SourceTypeRSS
	SourceTypeZip
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
		client: &http.Client{Timeout: 180 * time.Second}, // Very long timeout for large feeds
		sources: []DiscoverySource{
			// --- Vulnerability Databases ---
			{Name: "OSV npm Feed", URL: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip", Type: SourceTypeZip, Category: "vulnerability"},
			{Name: "NVD (NIST)", URL: "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", Type: SourceTypeRSS, Category: "vulnerability"},

			// --- Security Research & Organizations ---
			{Name: "Chaos Computer Club (CCC)", URL: "https://www.ccc.de/en/rss/updates.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "GitHub Security Lab", URL: "https://securitylab.github.com/feed.xml", Type: SourceTypeRSS, Category: "research"},
			{Name: "Google Open Source Security", URL: "https://security.googleblog.com/feeds/posts/default/-/Open%20Source%20Security", Type: SourceTypeRSS, Category: "research"},
			{Name: "OpenSSF Feed", URL: "https://openssf.org/blog/feed/", Type: SourceTypeRSS, Category: "research"},
			{Name: "Trail of Bits Blog", URL: "https://blog.trailofbits.com/feed/", Type: SourceTypeRSS, Category: "research"},
			{Name: "Krebs on Security", URL: "https://krebsonsecurity.com/feed/", Type: SourceTypeRSS, Category: "research"},
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
			// Log error but continue with other sources
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

	// Add User-Agent to avoid 403s and blocklisting
	req.Header.Set("User-Agent", "AuditterSecurityBot/1.0 (+https://github.com/kluth/npm-security-auditter)")

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
	case SourceTypeZip:
		return p.parseZip(resp, src)
	}

	return nil, nil
}

type rssFeed struct {
	Items   []rssItem `xml:"channel>item"`
	Entries []rssItem `xml:"entry"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Description string `xml:"description"`
	Link        string `xml:"link"`
	AtomLink    string `xml:"link,attr"`
}

func (p *UnifiedIntelProvider) parseRSS(resp *http.Response, src DiscoverySource) ([]IntelIssue, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var feed rssFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, err
	}

	var issues []IntelIssue
	// Handle RSS items
	for _, item := range feed.Items {
		issues = append(issues, p.createIssue(src, item))
	}
	// Handle Atom entries
	for _, entry := range feed.Entries {
		if entry.Link == "" && entry.AtomLink != "" {
			entry.Link = entry.AtomLink
		}
		issues = append(issues, p.createIssue(src, entry))
	}
	return issues, nil
}

func (p *UnifiedIntelProvider) createIssue(src DiscoverySource, item rssItem) IntelIssue {
	return IntelIssue{
		ID:          fmt.Sprintf("%s-%s", src.Name, item.Title),
		Type:        IssueTypeDetectionRule,
		Target:      "research",
		Description: fmt.Sprintf("[%s] %s: %s", src.Name, item.Title, item.Link),
		Severity:    analyzer.SeverityMedium,
		Source:      src.URL,
		UpdatedAt:   time.Now(),
		Metadata:    map[string]string{"link": item.Link, "category": src.Category},
	}
}

func (p *UnifiedIntelProvider) parseJSON(resp *http.Response, src DiscoverySource) ([]IntelIssue, error) {
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

func (p *UnifiedIntelProvider) parseZip(resp *http.Response, src DiscoverySource) ([]IntelIssue, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	r, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}

	var issues []IntelIssue
	// For OSV, each file is a JSON advisory. We only take the first few or a summary
	// for this simple unified provider to avoid memory bloat.
	count := 0
	for _, f := range r.File {
		if count > 100 { // Limit to 100 entries for the unified poller
			break
		}
		if !f.FileInfo().IsDir() && (bytes.HasSuffix([]byte(f.Name), []byte(".json"))) {
			issues = append(issues, IntelIssue{
				ID:          fmt.Sprintf("%s-%s", src.Name, f.Name),
				Type:        IssueTypeDetectionRule,
				Target:      "npm",
				Description: fmt.Sprintf("OSV Advisory: %s", f.Name),
				Severity:    analyzer.SeverityHigh,
				Source:      src.URL,
				UpdatedAt:   time.Now(),
			})
			count++
		}
	}
	return issues, nil
}
