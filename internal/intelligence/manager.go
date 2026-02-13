package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
)

// Manager coordinates polling from multiple intelligence sources.
type Manager struct {
	providers []Provider
	dataPath  string
	data      *Data
	mu        sync.RWMutex
}

// NewManager creates a new intelligence manager.
func NewManager(cacheDir string) *Manager {
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, ".cache", "auditter")
	}
	os.MkdirAll(cacheDir, 0755)

	return &Manager{
		dataPath: filepath.Join(cacheDir, "intelligence.json"),
		data:     &Data{},
	}
}

// AddProvider adds a new intelligence source.
func (m *Manager) AddProvider(p Provider) {
	m.providers = append(m.providers, p)
}

// Load loads cached intelligence data from disk.
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, err := os.Open(m.dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(m.data)
}

// Save persists intelligence data to disk.
func (m *Manager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.dataPath, data, 0644)
}

// Update polls all providers for new intelligence.
func (m *Manager) Update(ctx context.Context) error {
	var (
		allIssues []IntelIssue
		wg        sync.WaitGroup
		mu        sync.Mutex
		errors    []error
	)

	for _, p := range m.providers {
		wg.Add(1)
		go func(prov Provider) {
			defer wg.Done()
			issues, err := prov.Fetch(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errors = append(errors, fmt.Errorf("%s: %w", prov.Name(), err))
				return
			}
			allIssues = append(allIssues, issues...)
		}(p)
	}

	wg.Wait()

	m.mu.Lock()
	m.data.Issues = allIssues
	m.data.UpdatedAt = time.Now()
	m.mu.Unlock()

	if err := m.Save(); err != nil {
		return err
	}

	if len(errors) > 0 {
		for _, e := range errors {
			fmt.Printf("Provider error: %v\n", e)
		}
	}
	return nil
}

// AutoUpdate triggers an update only if the data is older than the threshold.
func (m *Manager) AutoUpdate(ctx context.Context, threshold time.Duration) {
	m.mu.RLock()
	stale := m.data.Stale(threshold)
	m.mu.RUnlock()

	if stale {
		// Run update in background context or synchronously depending on caller preference
		// For CLI tool, we usually want it to be fast, but security data is critical.
		// We'll run it synchronously for now but with a shorter timeout if called via AutoUpdate.
		m.Update(ctx)
	}
}

// GetIssuesByType returns all issues of a specific type.
func (m *Manager) GetIssuesByType(it IssueType) []IntelIssue {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []IntelIssue
	for _, issue := range m.data.Issues {
		if issue.Type == it {
			result = append(result, issue)
		}
	}
	return result
}

// IsMaliciousPackage checks if a package name is known to be malicious.
func (m *Manager) IsMaliciousPackage(name string) (bool, analyzer.MaliciousPackageResult) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, issue := range m.data.Issues {
		if issue.Type == IssueTypeMaliciousPackage && issue.Target == name {
			return true, analyzer.MaliciousPackageResult{
				IsMalicious: true,
				Description: issue.Description,
				Severity:    issue.Severity,
			}
		}
	}
	return false, analyzer.MaliciousPackageResult{}
}
