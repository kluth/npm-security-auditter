package intelligence

import (
	"context"
	"time"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
)

// IssueType identifies the type of security issue.
type IssueType string

const (
	IssueTypeMaliciousPackage IssueType = "malicious_package"
	IssueTypeSuspiciousIP     IssueType = "suspicious_ip"
	IssueTypeDetectionRule    IssueType = "detection_rule"
)

// IntelIssue represents a security issue retrieved from an online source.
type IntelIssue struct {
	ID          string            `json:"id"`
	Type        IssueType         `json:"type"`
	Target      string            `json:"target"` // package name, IP, etc.
	Description string            `json:"description"`
	Severity    analyzer.Severity `json:"severity"`
	Source      string            `json:"source"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Provider defines the interface for an intelligence source.
type Provider interface {
	Name() string
	Fetch(ctx context.Context) ([]IntelIssue, error)
}

// Data holds the aggregated intelligence information.
type Data struct {
	Issues    []IntelIssue `json:"issues"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// Stale returns true if the data is older than the given duration.
func (d *Data) Stale(maxAge time.Duration) bool {
	return time.Since(d.UpdatedAt) > maxAge
}
