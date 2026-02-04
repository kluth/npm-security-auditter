package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestProvenanceAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		pkg          *registry.PackageMetadata
		version      *registry.PackageVersion
		wantFindings int
		wantTitles   []string
	}{
		{
			name: "fully attested package",
			pkg: &registry.PackageMetadata{
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
			},
			version: &registry.PackageVersion{
				Dist: registry.Dist{
					Integrity: "sha512-abc123",
					Signatures: []registry.Signature{
						{Keyid: "key1", Sig: "sig1"},
					},
					Attestations: &registry.Attestations{URL: "https://example.com"},
				},
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
			},
			wantFindings: 0,
		},
		{
			name: "no signatures or attestations",
			pkg: &registry.PackageMetadata{
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
			},
			version: &registry.PackageVersion{
				Dist: registry.Dist{
					Integrity: "sha512-abc123",
				},
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
			},
			wantFindings: 2,
			wantTitles:   []string{"No registry signatures", "No provenance attestation"},
		},
		{
			name: "no integrity hash",
			pkg: &registry.PackageMetadata{
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
			},
			version: &registry.PackageVersion{
				Dist: registry.Dist{
					Signatures:   []registry.Signature{{Keyid: "key1", Sig: "sig1"}},
					Attestations: &registry.Attestations{URL: "https://example.com"},
				},
				Repository: &registry.Repository{URL: "https://github.com/user/repo"},
			},
			wantFindings: 1,
			wantTitles:   []string{"No integrity hash"},
		},
		{
			name:    "no repo link at all",
			pkg:     &registry.PackageMetadata{},
			version: &registry.PackageVersion{
				Dist: registry.Dist{
					Integrity:    "sha512-abc",
					Signatures:   []registry.Signature{{Keyid: "k", Sig: "s"}},
					Attestations: &registry.Attestations{URL: "u"},
				},
			},
			wantFindings: 1,
			wantTitles:   []string{"No source repository link"},
		},
		{
			name: "repo URL mismatch",
			pkg: &registry.PackageMetadata{
				Repository: &registry.Repository{URL: "https://github.com/user/repo-a"},
			},
			version: &registry.PackageVersion{
				Dist: registry.Dist{
					Integrity:    "sha512-abc",
					Signatures:   []registry.Signature{{Keyid: "k", Sig: "s"}},
					Attestations: &registry.Attestations{URL: "u"},
				},
				Repository: &registry.Repository{URL: "https://github.com/other/repo-b"},
			},
			wantFindings: 1,
			wantTitles:   []string{"Repository URL mismatch"},
		},
	}

	analyzer := NewProvenanceAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := analyzer.Analyze(context.Background(), tt.pkg, tt.version)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(findings) != tt.wantFindings {
				t.Errorf("Analyze() returned %d findings, want %d. Findings: %+v",
					len(findings), tt.wantFindings, findings)
			}
			for i, title := range tt.wantTitles {
				if i < len(findings) && findings[i].Title != title {
					t.Errorf("findings[%d].Title = %q, want %q", i, findings[i].Title, title)
				}
			}
		})
	}
}

func TestNormalizeRepoURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://github.com/user/repo.git", "github.com/user/repo"},
		{"git+https://github.com/user/repo.git", "github.com/user/repo"},
		{"git://github.com/user/repo", "github.com/user/repo"},
		{"https://github.com/user/repo/", "github.com/user/repo"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeRepoURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeRepoURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
