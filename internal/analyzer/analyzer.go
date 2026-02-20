package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	// SeverityLow indicates an informational finding or minor risk.
	SeverityLow Severity = iota
	// SeverityMedium indicates a moderate security risk that should be reviewed.
	SeverityMedium
	// SeverityHigh indicates a serious security risk that needs immediate attention.
	SeverityHigh
	// SeverityCritical indicates a verified malicious pattern or critical vulnerability.
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
	File           string   `json:"file,omitempty"`
	Line           int      `json:"line,omitempty"`
	Column         int      `json:"column,omitempty"`
	CodeExtract    string   `json:"code_extract,omitempty"`
}

// Analyzer is the interface that all security analyzers implement.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error)
}

// Result holds the output of a single analyzer run.
type Result struct {
	// AnalyzerName is the name of the analyzer that was run.
	AnalyzerName string
	// Findings is the list of security findings found by the analyzer.
	Findings     []Finding
	// Err is any error that occurred during the analysis.
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

var (
	singleLineComment = regexp.MustCompile(`(?m)(^|\s)//.*`)
	multiLineComment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// StripComments removes both single-line and multi-line comments from JavaScript/TypeScript code
// while preserving line numbers by replacing comment characters with spaces.
func StripComments(content string) string {
	// Remove multi-line comments preserving newlines
	content = multiLineComment.ReplaceAllStringFunc(content, func(s string) string {
		var res strings.Builder
		for _, r := range s {
			if r == '\n' {
				res.WriteRune('\n')
			} else {
				res.WriteRune(' ')
			}
		}
		return res.String()
	})

	// Remove single-line comments preserving newlines
	content = singleLineComment.ReplaceAllStringFunc(content, func(s string) string {
		return strings.Repeat(" ", len(s))
	})

	return content
}

// GetLineCol returns the 1-based line and column number for a given byte offset.
func GetLineCol(content string, offset int) (int, int) {
	if offset < 0 || offset > len(content) {
		return 0, 0
	}
	line := 1
	col := 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// GetCodeExtract returns a snippet of code around the given range.
func GetCodeExtract(content string, start, end int, contextLines int) string {
	if start < 0 || end > len(content) || start > end {
		return ""
	}

	lines := strings.Split(content, "\n")
	startLine, _ := GetLineCol(content, start)
	
	s := startLine - contextLines - 1
	if s < 0 {
		s = 0
	}
	e := startLine + contextLines
	if e > len(lines) {
		e = len(lines)
	}

	var res strings.Builder
	for i := s; i < e; i++ {
		prefix := "  "
		if i == startLine-1 {
			prefix = "> "
		}
		res.WriteString(fmt.Sprintf("%s%d: %s\n", prefix, i+1, lines[i]))
	}
	return res.String()
}
