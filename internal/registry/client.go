package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultRegistry     = "https://registry.npmjs.org"
	DefaultDownloadsAPI = "https://api.npmjs.org"
)

// Client is an HTTP client for the npm registry.
type Client struct {
	httpClient   *http.Client
	registryURL  string
	downloadsURL string
}

// NewClient creates a new registry client. If registryURL is empty, the default
// npm registry is used.
func NewClient(registryURL string) *Client {
	if registryURL == "" {
		registryURL = DefaultRegistry
	}
	registryURL = strings.TrimRight(registryURL, "/")

	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		registryURL:  registryURL,
		downloadsURL: DefaultDownloadsAPI,
	}
}

// GetPackage fetches full metadata for a package from the registry.
func (c *Client) GetPackage(ctx context.Context, name string) (*PackageMetadata, error) {
	encodedName := url.PathEscape(name)
	reqURL := fmt.Sprintf("%s/%s", c.registryURL, encodedName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching package %q: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("package %q: registry returned status %d", name, resp.StatusCode)
	}

	var metadata PackageMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decoding package %q: %w", name, err)
	}

	return &metadata, nil
}

// GetDownloads fetches download counts for a package over the last week.
func (c *Client) GetDownloads(ctx context.Context, name string) (*DownloadCount, error) {
	reqURL := fmt.Sprintf("%s/downloads/point/last-week/%s", c.downloadsURL, url.PathEscape(name))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating downloads request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching downloads for %q: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloads for %q: API returned status %d", name, resp.StatusCode)
	}

	var dl DownloadCount
	if err := json.NewDecoder(resp.Body).Decode(&dl); err != nil {
		return nil, fmt.Errorf("decoding downloads for %q: %w", name, err)
	}

	return &dl, nil
}
