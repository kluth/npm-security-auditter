package analyzer

import (
	"context"
	"sync"

	"github.com/matthias/auditter/internal/registry"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Finding represents a single security finding from an analyzer.
type Finding struct {
	Analyzer       string   `json:"analyzer"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       Severity `json:"severity"`
	ExploitExample string   `json:"exploit_example,omitempty"`
	Remediation    string   `json:"remediation,omitempty"`
}

// Analyzer is the interface that all security analyzers implement.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error)
}

// Result holds the output of a single analyzer run.
type Result struct {
	AnalyzerName string
	Findings     []Finding
	Err          error
}

// RunAll runs all analyzers concurrently and returns their results.
func RunAll(ctx context.Context, analyzers []Analyzer, pkg *registry.PackageMetadata, version *registry.PackageVersion) []Result {
	results := make([]Result, len(analyzers))
	var wg sync.WaitGroup

	for i, a := range analyzers {
		wg.Add(1)
		go func(idx int, analyzer Analyzer) {
			defer wg.Done()
			findings, err := analyzer.Analyze(ctx, pkg, version)
			results[idx] = Result{
				AnalyzerName: analyzer.Name(),
				Findings:     findings,
				Err:          err,
			}
		}(i, a)
	}

	wg.Wait()
	return results
}

// FilterByMinSeverity filters findings to only include those at or above the given severity.
func FilterByMinSeverity(findings []Finding, minSeverity Severity) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if f.Severity >= minSeverity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
