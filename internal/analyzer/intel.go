package analyzer

import (
	"context"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// MaliciousPackageResult holds the result of a malicious package check.
type MaliciousPackageResult struct {
	IsMalicious bool
	Description string
	Severity    Severity
}

// IntelligenceManager defines the interface for checking intelligence data.
type IntelligenceManager interface {
	IsMaliciousPackage(name string) (bool, MaliciousPackageResult)
}

// IntelAnalyzer checks packages against intelligence data.
type IntelAnalyzer struct {
	manager IntelligenceManager
}

// NewIntelAnalyzer creates a new intelligence-based analyzer.
func NewIntelAnalyzer(m IntelligenceManager) *IntelAnalyzer {
	return &IntelAnalyzer{manager: m}
}

func (a *IntelAnalyzer) Name() string { return "threat-intel" }

func (a *IntelAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	if a.manager == nil {
		return nil, nil
	}

	found, res := a.manager.IsMaliciousPackage(pkg.Name)
	if !found || !res.IsMalicious {
		return nil, nil
	}

	return []Finding{
		{
			Analyzer:    a.Name(),
			Title:       "Known Malicious Package",
			Description: res.Description,
			Severity:    res.Severity,
			Remediation: "DO NOT INSTALL. If already installed, remove immediately and rotate all credentials handled by the affected systems.",
		},
	}, nil
}
