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
	"os"
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
		_, _ = w.Write(data)
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
		_, _ = w.Write(data)
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
		_, _ = w.Write(data)
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
	// Garbage characters that don't look like minified code (many short lines)
	garbageLines := strings.Repeat("!@#$%^&*()_+\n", 20)
	base64Str := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 10) // 640 chars

	// High entropy data that is NOT minified (has many short lines to avoid minification detection)
	var highEntropyParts []string
	for i := 0; i < 50; i++ {
		part := make([]byte, 20)
		for j := range part {
			part[j] = byte((i*j*13)%94 + 33) // Printable high entropy
		}
		highEntropyParts = append(highEntropyParts, string(part))
	}
	highEntropy := strings.Join(highEntropyParts, "\n") // Many short lines = not minified

	files := map[string]string{
		"package.json":    `{"name":"test","version":"1.0.0"}`,
		"highratio.js":    garbageLines,
		"encoded.js":      `var payload = "` + base64Str + `";`,
		"binary.exe":      "MZ9000", // minimal PE header stub
		"high_entropy.js": highEntropy,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
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
		"High non-alphanumeric ratio",
		"Long base64-encoded string",
		"Dangerous file extension detected",
		"High entropy content",
		"Extremely high entropy content",
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
		_, _ = w.Write(data)
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
		_, _ = w.Write(data)
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

func TestTarballAnalyzer_LargeJSFile(t *testing.T) {
	// Create a JS file larger than 1MB
	largeJS := strings.Repeat("var x = 1;\n", 200000) // ~2.2MB
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		"large.js":     largeJS,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name: "test", Version: "1.0.0",
		Dist: registry.Dist{Tarball: srv.URL + "/test.tgz", Shasum: shasum},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "Large file detected" {
			found = true
			if f.Severity != SeverityMedium {
				t.Error("expected SeverityMedium for large JS file")
			}
		}
	}
	if !found {
		t.Error("expected 'Large file detected' finding for large JS file")
	}
}

func TestTarballAnalyzer_LargeNonJSFile(t *testing.T) {
	largeData := strings.Repeat("data\n", 300000) // ~1.5MB
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		"large.dat":    largeData,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name: "test", Version: "1.0.0",
		Dist: registry.Dist{Tarball: srv.URL + "/test.tgz", Shasum: shasum},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "Large file detected" && f.Severity == SeverityLow {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Large file detected' with SeverityLow for non-JS file")
	}
}

func TestTarballAnalyzer_SensitiveDirectory(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		".ssh/id_rsa":  "private key",
		".aws/creds":   "secret",
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name: "test", Version: "1.0.0",
		Dist: registry.Dist{Tarball: srv.URL + "/test.tgz", Shasum: shasum},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	dirCount := 0
	for _, f := range findings {
		if f.Title == "Sensitive directory in package" {
			dirCount++
		}
	}
	if dirCount < 2 {
		t.Errorf("expected at least 2 sensitive directory findings, got %d", dirCount)
	}
}

func TestTarballAnalyzer_ComparePackageJSON_NoPackageJSON(t *testing.T) {
	a := NewTarballAnalyzer()
	ep := &tarball.ExtractedPackage{PackageJSON: nil}
	findings := a.comparePackageJSON(ep, &registry.PackageVersion{})
	if len(findings) != 0 {
		t.Error("expected 0 findings when no package.json")
	}
}

func TestTarballAnalyzer_ComparePackageJSON_InvalidJSON(t *testing.T) {
	a := NewTarballAnalyzer()
	ep := &tarball.ExtractedPackage{PackageJSON: []byte(`{invalid`)}
	findings := a.comparePackageJSON(ep, &registry.PackageVersion{})
	if len(findings) != 0 {
		t.Error("expected 0 findings for invalid package.json")
	}
}

func TestReadFileHead(t *testing.T) {
	_, err := readFileHead("/nonexistent/path", 8)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadFileHead_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.bin"
	if err := os.WriteFile(path, []byte{0x4d, 0x5a, 0x90, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}

	data, err := readFileHead(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(data))
	}
}

func TestReadFileHead_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/empty.bin"
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := readFileHead(path, 8)
	if err == nil {
		t.Error("expected EOF error for empty file")
	}
}

func TestTarballAnalyzer_DownloadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name: "test", Version: "1.0.0",
		Dist: registry.Dist{Tarball: srv.URL + "/test.tgz", Shasum: "abc"},
	}

	_, err := a.Analyze(context.Background(), pkg, version)
	if err == nil {
		t.Error("expected error for download failure")
	}
}

func TestTarballAnalyzer_BinaryMagicBytes(t *testing.T) {
	// PE executable magic bytes
	peHeader := string([]byte{0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00})
	// Mach-O 64-bit
	machoHeader := string([]byte{0xfe, 0xed, 0xfa, 0xcf, 0x00, 0x00, 0x00, 0x00})

	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		"win.bin":      peHeader,
		"mac.bin":      machoHeader,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name: "test", Version: "1.0.0",
		Dist: registry.Dist{Tarball: srv.URL + "/test.tgz", Shasum: shasum},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}

	peFound := false
	machoFound := false
	for _, f := range findings {
		if strings.Contains(f.Title, "PE executable") {
			peFound = true
		}
		if strings.Contains(f.Title, "Mach-O binary (64-bit)") {
			machoFound = true
		}
	}
	if !peFound {
		t.Error("expected PE executable finding")
	}
	if !machoFound {
		t.Error("expected Mach-O 64-bit finding")
	}
}

func TestTarballAnalyzer_ReadError(t *testing.T) {
	// Setup a fake EP with a file that doesn't exist
	ep := &tarball.ExtractedPackage{
		Dir: "/tmp/non-existent-dir-12345",
		Files: []tarball.FileEntry{
			{Path: "missing.js", IsJS: true, Size: 500},
		},
	}

	a := NewTarballAnalyzer()

	// All these should handle missing file errors gracefully
	if f := a.scanJSFiles(ep); len(f) != 0 {
		t.Error("expected 0 findings for missing file in scanJSFiles")
	}
	if f := a.detectObfuscation(ep); len(f) != 0 {
		t.Error("expected 0 findings for missing file in detectObfuscation")
	}
	if f := a.findEncodedPayloads(ep); len(f) != 0 {
		t.Error("expected 0 findings for missing file in findEncodedPayloads")
	}
	if f := a.entropyAnalysis(ep); len(f) != 0 {
		t.Error("expected 0 findings for missing file in entropyAnalysis")
	}
	if f := a.findCryptoWallets(ep); len(f) != 0 {
		t.Error("expected 0 findings for missing file in findCryptoWallets")
	}
	if f := a.checkMalwareSignatures(ep); len(f) != 0 {
		t.Error("expected 0 findings for missing file in checkMalwareSignatures")
	}
}

func TestTarballAnalyzer_DetectBinaries_ShortFile(t *testing.T) {
	// File with only 1 byte - too short for magic byte detection
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		"tiny.bin":     "x",
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name: "test", Version: "1.0.0",
		Dist: registry.Dist{Tarball: srv.URL + "/test.tgz", Shasum: shasum},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}
	// Tiny file should not trigger binary detection
	for _, f := range findings {
		if strings.Contains(f.Title, "Binary detected") {
			t.Error("should not detect binary for 1-byte file")
		}
	}
}

func TestTarballAnalyzer_EncodedPayloads_SmallFile(t *testing.T) {
	// JS file with <= 256 bytes should not trigger entropy check in findEncodedPayloads
	smallJS := `var x = 1;`
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
		"small.js":     smallJS,
	}
	data, shasum := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name: "test", Version: "1.0.0",
		Dist: registry.Dist{Tarball: srv.URL + "/test.tgz", Shasum: shasum},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Title == "Highly complex or randomized content" {
			t.Error("should not trigger entropy check on small file")
		}
	}
}

func TestTarballAnalyzer_ShasumMismatch(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"test","version":"1.0.0"}`,
	}
	data, _ := makeTarballData(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	a := NewTarballAnalyzer()
	pkg := &registry.PackageMetadata{Name: "test"}
	version := &registry.PackageVersion{
		Name: "test", Version: "1.0.0",
		Dist: registry.Dist{
			Tarball: srv.URL + "/test.tgz",
			Shasum:  "0000000000000000000000000000000000000000",
		},
	}

	findings, err := a.Analyze(context.Background(), pkg, version)
	if err != nil {
		t.Fatal("should not return error for shasum mismatch, should return findings")
	}
	found := false
	for _, f := range findings {
		if f.Title == "Tarball SHA-1 mismatch" {
			found = true
			if f.Severity != SeverityCritical {
				t.Error("expected SeverityCritical for shasum mismatch")
			}
		}
	}
	if !found {
		t.Error("expected 'Tarball SHA-1 mismatch' finding")
	}
}

func TestTarballAnalyzer_NonJSFilesSkipped(t *testing.T) {
	// Non-JS files should be skipped by scanJSFiles, findEncodedPayloads, entropyAnalysis, findCryptoWallets
	ep := &tarball.ExtractedPackage{
		Dir: "/tmp",
		Files: []tarball.FileEntry{
			{Path: "readme.md", IsJS: false, Size: 500},
		},
	}

	a := NewTarballAnalyzer()
	if f := a.scanJSFiles(ep); len(f) != 0 {
		t.Error("non-JS should be skipped")
	}
	if f := a.detectObfuscation(ep); len(f) != 0 {
		t.Error("non-JS should be skipped for obfuscation")
	}
	if f := a.findEncodedPayloads(ep); len(f) != 0 {
		t.Error("non-JS should be skipped for encoded payloads")
	}
	if f := a.findCryptoWallets(ep); len(f) != 0 {
		t.Error("non-JS should be skipped for crypto wallets")
	}
}

func TestTarballAnalyzer_EntropyAnalysis_SmallJSFile(t *testing.T) {
	// JS file with size < 256 should be skipped by entropyAnalysis
	ep := &tarball.ExtractedPackage{
		Dir: "/tmp",
		Files: []tarball.FileEntry{
			{Path: "small.js", IsJS: true, Size: 100},
		},
	}

	a := NewTarballAnalyzer()
	if f := a.entropyAnalysis(ep); len(f) != 0 {
		t.Error("small JS file should be skipped by entropyAnalysis")
	}
}
