package analyzer

import (
	"context"
	"strings"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestReproducibleBuildAnalyzer_Name(t *testing.T) {
	a := NewReproducibleBuildAnalyzer()
	if a.Name() != "reproducible-build" {
		t.Errorf("expected name 'reproducible-build', got %q", a.Name())
	}
}

func TestReproducibleBuildAnalyzer_NoProvenance(t *testing.T) {
	a := NewReproducibleBuildAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball:   "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Integrity: "",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "integrity") || strings.Contains(f.Title, "Integrity") || strings.Contains(f.Title, "provenance") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for missing integrity hash")
	}
}

func TestReproducibleBuildAnalyzer_NoAttestations(t *testing.T) {
	a := NewReproducibleBuildAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball:   "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Integrity: "sha512-abc123",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "attestation") || strings.Contains(f.Title, "Attestation") || strings.Contains(f.Title, "provenance") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for missing attestations")
	}
}

func TestReproducibleBuildAnalyzer_NoSignatures(t *testing.T) {
	a := NewReproducibleBuildAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball:   "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Integrity: "sha512-abc123",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "signature") || strings.Contains(f.Title, "Signature") || strings.Contains(f.Title, "sign") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for missing registry signatures")
	}
}

func TestReproducibleBuildAnalyzer_NoRepo(t *testing.T) {
	a := NewReproducibleBuildAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball:      "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Integrity:    "sha512-abc123",
			Signatures:   []registry.Signature{{Keyid: "key1", Sig: "sig1"}},
			Attestations: &registry.Attestations{URL: "https://example.com"},
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "source verification") || strings.Contains(f.Title, "repository") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for inability to verify build against source")
	}
}

func TestReproducibleBuildAnalyzer_FullyVerifiable(t *testing.T) {
	a := NewReproducibleBuildAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{
		Name: "test-pkg",
		Repository: &registry.Repository{
			URL: "https://github.com/user/test-pkg",
		},
	}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Repository: &registry.Repository{
			URL: "https://github.com/user/test-pkg",
		},
		Dist: registry.Dist{
			Tarball:      "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Integrity:    "sha512-abc123",
			Signatures:   []registry.Signature{{Keyid: "key1", Sig: "sig1"}},
			Attestations: &registry.Attestations{URL: "https://example.com"},
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity for verifiable package: %s", f.Title)
		}
	}
}

func TestReproducibleBuildAnalyzer_WeakIntegrity(t *testing.T) {
	a := NewReproducibleBuildAnalyzer()
	ctx := context.Background()
	pkg := &registry.PackageMetadata{Name: "test-pkg"}
	version := &registry.PackageVersion{
		Name:    "test-pkg",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball:   "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
			Integrity: "sha1-weakHash",
			Shasum:    "abc123",
		},
	}

	findings, err := a.Analyze(ctx, pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SHA-1") || strings.Contains(f.Title, "weak") || strings.Contains(f.Title, "Weak") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for weak SHA-1 integrity hash")
	}
}
