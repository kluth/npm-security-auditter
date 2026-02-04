package analyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/tarball"
)

func makeTarballData(t *testing.T, files map[string]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	hasher := sha1.New()
	w := io.MultiWriter(&buf, hasher)
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	for name, content := range files {
		hdr := &tar.Header{
			Name:     "package/" + name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}

	tw.Close()
	gzw.Close()

	shasum := hex.EncodeToString(hasher.Sum(nil))
	return buf.Bytes(), shasum
}

func TestTarballAnalyzer_MaliciousPatterns(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		"index.js":     `const cp = require('child_process'); cp.exec('rm -rf /');`,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name:    "test",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: srv.URL + "/test.tgz",
			Shasum:  shasum,
		},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Error("expected findings for malicious patterns")
	}

	foundCP := false
	for _, f := range findings {
		if f.Title == "Suspicious pattern: child_process require" {
			foundCP = true
		}
	}
	if !foundCP {
		t.Error("expected child_process finding")
	}
}

func TestTarballAnalyzer_HiddenFiles(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		".env":         `SECRET_KEY=abc123`,
		".npmrc":       `//registry.npmjs.org/:_authToken=xyz`,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name:    "test",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: srv.URL + "/test.tgz",
			Shasum:  shasum,
		},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	hiddenCount := 0
	for _, f := range findings {
		if f.Title == "Hidden/sensitive file in package" {
			hiddenCount++
		}
	}
	if hiddenCount < 2 {
		t.Errorf("expected at least 2 hidden file findings, got %d", hiddenCount)
	}
}

func TestTarballAnalyzer_PackageNameMismatch(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"evil-package","version":"1.0.0"}`,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "good-package"}
	version := &registry.PackageVersion{
		Name:    "good-package",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: srv.URL + "/test.tgz",
			Shasum:  shasum,
		},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "Package name mismatch" {
			found = true
		}
	}
	if !found {
		t.Error("expected package name mismatch finding")
	}
}

func TestTarballAnalyzer_NoTarball(t *testing.T) {
	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name:    "test",
		Version: "1.0.0",
	}

	_, err := a.Analyze(context.Background(), pkg, version)
	if err == nil {
		t.Error("expected error when no tarball URL")
	}
}

func TestShannonEntropy(t *testing.T) {
	// All same bytes -> 0 entropy.
	data := bytes.Repeat([]byte{0x41}, 1000)
	e := shannonEntropy(data)
	if e != 0 {
		t.Errorf("expected 0 entropy for uniform data, got %f", e)
	}

	// Random-ish data -> higher entropy.
	mixed := make([]byte, 1000)
	for i := range mixed {
		mixed[i] = byte(i % 256)
	}
	e = shannonEntropy(mixed)
	if e < 7.0 {
		t.Errorf("expected high entropy for varied data, got %f", e)
	}

	// Empty data -> 0.
	e = shannonEntropy(nil)
	if e != 0 {
		t.Errorf("expected 0 entropy for nil, got %f", e)
	}
}

func TestTarballAnalyzer_Name(t *testing.T) {
	a := NewTarballAnalyzer()
	if a.Name() != "tarball-analysis" {
		t.Errorf("expected 'tarball-analysis', got %q", a.Name())
	}
}

func TestTarballAnalyzer_Obfuscation_And_Entropy(t *testing.T) {
	longLine := strings.Repeat("var a=1;", 1000) // 8000 chars
	garbage := "!!!!@@@@####$$$$%%%%^^^^&&&&****(((())))____++++====~~~~" + strings.Repeat(";", 100)
	base64Str := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 10) // 640 chars

	// High entropy data
	highEntropy := make([]byte, 1000)
	for i := range highEntropy {
		highEntropy[i] = byte((i * 13) % 256) // Pseudo-random distribution
	}

	files := map[string]string{
		"package.json":    `{"name":"test","version":"1.0.0"}`,
		"longlines.js":    longLine,
		"highratio.js":    garbage,
		"encoded.js":      `var payload = "` + base64Str + `";`,
		"binary.exe":      "MZ9000", // minimal PE header stub
		"high_entropy.js": string(highEntropy),
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name:    "test",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: srv.URL + "/test.tgz",
			Shasum:  shasum,
		},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	expectedTitles := []string{
		"Extremely long lines (likely minified/obfuscated)",
		"High non-alphanumeric ratio",
		"Long base64-encoded string",
		"Compiled binary in package",
		"Very high file entropy (likely obfuscated)",
	}

	foundTitles := make(map[string]bool)
	for _, f := range findings {
		foundTitles[f.Title] = true
	}

	for _, title := range expectedTitles {
		if !foundTitles[title] {
			t.Errorf("expected finding %q not found", title)
		}
	}
}

func TestTarballAnalyzer_Crypto_And_Malware(t *testing.T) {
	elfHeader := string([]byte{0x7f, 0x45, 0x4c, 0x46})
	
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		"wallet.js":    `const wallet = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";`,
		"malware.js":   `var url = "https://sstatic1.histats.com/script";`,
		"linux_bin":    elfHeader + "...",
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name:    "test",
		Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: srv.URL + "/test.tgz",
			Shasum:  shasum,
		},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	expectedTitles := []string{
		"Cryptocurrency address found: Ethereum address",
		"Known malware signature: rc/systeminformation exfil",
		"Binary detected: ELF binary",
	}

	foundTitles := make(map[string]bool)
	for _, f := range findings {
		foundTitles[f.Title] = true
	}

	for _, title := range expectedTitles {
		if !foundTitles[title] {
			t.Errorf("expected finding %q not found", title)
		}
	}
}

func TestTarballAnalyzer_PackageJSON(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"hidden-deps-pkg","version":"1.0.0","scripts":{"preinstall":"evil.sh"},"dependencies":{"evil-lib":"1.0.0"}}`,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "public-pkg"}
	version := &registry.PackageVersion{
		Name:    "public-pkg",
		Version: "1.0.0",
		// Empty scripts/deps in registry
		Scripts:      map[string]string{},
		Dependencies: map[string]string{},
		Dist: registry.Dist{
			Tarball: srv.URL + "/test.tgz",
			Shasum:  shasum,
		},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	expectedTitles := []string{
		"Package name mismatch",
		"Hidden install script in tarball",
		"Hidden dependency in tarball",
	}

	foundTitles := make(map[string]bool)
	for _, f := range findings {
		foundTitles[f.Title] = true
	}

	for _, title := range expectedTitles {
		if !foundTitles[title] {
			t.Errorf("expected finding %q not found", title)
		}
	}
}

func TestTarballAnalyzer_ReadError(t *testing.T) {
	// Setup a fake EP with a file that doesn't exist
	ep := &tarball.ExtractedPackage{
		Dir: "/tmp/non-existent-dir-12345",
		Files: []tarball.FileEntry{
			{Path: "missing.js", IsJS: true, Size: 100},
		},
	}

	a := NewTarballAnalyzer()
	
	// These shouldn't panic and should handle errors gracefully (return empty findings)
	f1 := a.scanJSFiles(ep)
	if len(f1) != 0 {
		t.Error("expected 0 findings for missing file")
	}
	f2 := a.detectObfuscation(ep)
	if len(f2) != 0 {
		t.Error("expected 0 findings for missing file")
	}
	// ... check other methods if needed
}

