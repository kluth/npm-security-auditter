package analyzer

import (
	"context"
	"strings"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestCodeSigningAnalyzer_Name(t *testing.T) {
	a := NewCodeSigningAnalyzer()
	if a.Name() != "code-signing" {
		t.Errorf("expected name 'code-signing', got %q", a.Name())
	}
}

func TestCodeSigningAnalyzer_NoSignatures(t *testing.T) {
	a := NewCodeSigningAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "unsigned") || strings.Contains(f.Title, "Unsigned") || strings.Contains(f.Title, "No signature") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for unsigned package")
	}
}

func TestCodeSigningAnalyzer_HasSignature(t *testing.T) {
	a := NewCodeSigningAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Signatures: []registry.Signature{
				{Keyid: "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA", Sig: "abc123"},
			},
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	// Should not have any critical or high findings for signed package
	for _, f := range findings {
		if f.Severity >= SeverityHigh && strings.Contains(f.Title, "sign") {
			t.Errorf("Unexpected high severity signing finding for signed package: %s", f.Title)
		}
	}
}

func TestCodeSigningAnalyzer_HasAttestationsAndSignature(t *testing.T) {
	a := NewCodeSigningAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball:   "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Integrity: "sha512-validhash",
			Signatures: []registry.Signature{
				{Keyid: "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA", Sig: "MEUCIQDg9MpSLkNfE0UGBLM5VYPzfGNeWFBjlBpNm2qDy6dvLQIgYf4hTP+P7Gq1FX"},
			},
			Attestations: &registry.Attestations{
				URL: "https://registry.npmjs.org/-/npm/v1/attestations/test-pkg@1.0.0",
				Provenance: &registry.Provenance{
					PredicateType: "https://slsa.dev/provenance/v1",
				},
			},
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	// Fully signed + attested package should have no significant findings
	for _, f := range findings {
		if f.Severity >= SeverityMedium {
			t.Errorf("Unexpected finding for fully signed package: %s (severity: %v)", f.Title, f.Severity)
		}
	}
}

func TestCodeSigningAnalyzer_WeakKeyID(t *testing.T) {
	a := NewCodeSigningAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Signatures: []registry.Signature{
				{Keyid: "abc", Sig: "xyz"}, // Suspiciously short key ID
			},
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "key") || strings.Contains(f.Title, "Key") || strings.Contains(f.Title, "weak") || strings.Contains(f.Title, "Weak") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for weak/short key ID")
	}
}

func TestCodeSigningAnalyzer_SLSAProvenance(t *testing.T) {
	a := NewCodeSigningAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Attestations: &registry.Attestations{
				URL: "https://registry.npmjs.org/-/npm/v1/attestations/test-pkg@1.0.0",
				Provenance: &registry.Provenance{
					PredicateType: "https://slsa.dev/provenance/v1",
				},
			},
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	// Should flag missing signatures but should recognize attestation
	hasSigFinding := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Unsigned") || strings.Contains(f.Title, "No signature") {
			hasSigFinding = true
		}
	}
	if !hasSigFinding {
		t.Error("Expected finding for missing signature even with attestation")
	}
}
