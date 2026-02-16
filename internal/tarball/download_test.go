package tarball

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func makeTarball(t *testing.T, files map[string]string) ([]byte, string) {
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

func TestDownload_Success(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name": "test", "version": "1.0.0"}`,
		"index.js":     `console.log("hello");`,
		"lib/util.js":  `module.exports = {};`,
	}
	data, shasum := makeTarball(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	ep, err := Download(context.Background(), srv.URL+"/test.tgz", shasum)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Cleanup()

	if len(ep.Files) != 3 {
		t.Errorf("expected 3 files, got %d", len(ep.Files))
	}

	if ep.PackageJSON == nil {
		t.Error("expected package.json to be captured")
	}

	// Verify JS detection.
	jsCount := 0
	for _, f := range ep.Files {
		if f.IsJS {
			jsCount++
		}
	}
	if jsCount != 2 {
		t.Errorf("expected 2 JS files, got %d", jsCount)
	}
}

func TestDownload_ShasumMismatch(t *testing.T) {
	files := map[string]string{
		"index.js": `console.log("hello");`,
	}
	data, _ := makeTarball(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	_, err := Download(context.Background(), srv.URL+"/test.tgz", "0000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected error for shasum mismatch")
	}

	var mismatch *ShasumMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("expected ShasumMismatchError, got %T: %v", err, err)
	}
	if mismatch.Error() == "" {
		t.Error("expected ShasumMismatchError.Error() to be non-empty")
	}
}

func TestDownload_Errors(t *testing.T) {
	t.Run("HTTP 404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := Download(context.Background(), srv.URL+"/test.tgz", "")
		if err == nil {
			t.Fatal("expected error for 404")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("status 404")) {
			t.Errorf("expected status 404 error, got: %v", err)
		}
	})

	t.Run("Invalid Gzip", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not gzip data"))
		}))
		defer srv.Close()

		_, err := Download(context.Background(), srv.URL+"/test.tgz", "")
		if err == nil {
			t.Fatal("expected error for invalid gzip")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("gzip reader")) {
			t.Errorf("expected gzip reader error, got: %v", err)
		}
	})

	t.Run("Corrupt Tar", func(t *testing.T) {
		// Valid gzip header but bad content
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write([]byte("not a tar")); err != nil {
			t.Fatal(err)
		}
		gz.Close()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(buf.Bytes())
		}))
		defer srv.Close()

		_, err := Download(context.Background(), srv.URL+"/test.tgz", "")
		if err == nil {
			t.Fatal("expected error for corrupt tar")
		}
		// "reading tar: unexpected EOF" or similar
		if !bytes.Contains([]byte(err.Error()), []byte("reading tar")) {
			t.Errorf("expected reading tar error, got: %v", err)
		}
	})
}

func TestDownload_PathTraversal(t *testing.T) {
	var buf bytes.Buffer
	hasher := sha1.New()
	w := io.MultiWriter(&buf, hasher)
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	hdr := &tar.Header{
		Name:     "package/../../etc/passwd",
		Mode:     0o644,
		Size:     5,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("evil\n")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gzw.Close()

	shasum := hex.EncodeToString(hasher.Sum(nil))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	// Path traversal entries are silently skipped (sanitizePath returns "").
	ep, err := Download(context.Background(), srv.URL+"/test.tgz", shasum)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Cleanup()

	// The traversal file should not have been extracted.
	if len(ep.Files) != 0 {
		t.Errorf("expected 0 files (traversal skipped), got %d", len(ep.Files))
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"package/index.js", "index.js"},
		{"package/lib/util.js", "lib/util.js"},
		{"../etc/passwd", ""},
		{"package/../../../etc/passwd", ""},
		{"", ""},
		{".", ""},
	}

	for _, tt := range tests {
		got := sanitizePath(tt.input)
		if got != tt.want {
			t.Errorf("sanitizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCleanup(t *testing.T) {
	// Nil package
	var ep *ExtractedPackage
	ep.Cleanup() // should not panic

	// Empty dir
	ep2 := &ExtractedPackage{Dir: ""}
	ep2.Cleanup() // should not panic

	// Valid dir
	dir := t.TempDir()
	ep3 := &ExtractedPackage{Dir: dir}
	ep3.Cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("expected dir to be removed after cleanup")
	}
}

func TestDownload_EmptyShasum(t *testing.T) {
	files := map[string]string{
		"index.js": `console.log("hello");`,
	}
	data, _ := makeTarball(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	// Empty shasum should not cause an error (verification is skipped)
	ep, err := Download(context.Background(), srv.URL+"/test.tgz", "")
	if err != nil {
		t.Fatalf("expected no error with empty shasum, got %v", err)
	}
	defer ep.Cleanup()
}

func TestDownload_DirectoryEntry(t *testing.T) {
	// Create a tarball with a directory entry (TypeDir) that should be skipped
	var buf bytes.Buffer
	hasher := sha1.New()
	w := io.MultiWriter(&buf, hasher)
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	// Add a directory entry
	if err := tw.WriteHeader(&tar.Header{
		Name:     "package/lib/",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		t.Fatal(err)
	}

	// Add a regular file
	content := []byte(`console.log("hello");`)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "package/index.js",
		Mode:     0o644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gzw.Close()

	shasum := hex.EncodeToString(hasher.Sum(nil))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	ep, err := Download(context.Background(), srv.URL+"/test.tgz", shasum)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Cleanup()

	// Only the regular file should be in the list, not the directory
	if len(ep.Files) != 1 {
		t.Errorf("expected 1 file (skipping dir entry), got %d", len(ep.Files))
	}
}

func TestSanitizePath_Absolute(t *testing.T) {
	got := sanitizePath("/etc/passwd")
	if got != "" {
		t.Errorf("expected empty for absolute path, got %q", got)
	}
}

func TestDownload_OversizedFile(t *testing.T) {
	// Create a tarball with a header claiming a file >10MB (maxFileSize)
	var buf bytes.Buffer
	hasher := sha1.New()
	w := io.MultiWriter(&buf, hasher)
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	// Write a header with Size > maxFileSize but don't actually write that much data
	if err := tw.WriteHeader(&tar.Header{
		Name:     "package/huge.js",
		Mode:     0o644,
		Size:     11 * 1024 * 1024, // 11MB, exceeds 10MB limit
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	// Write minimal actual data (tar will pad)
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gzw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	_, err := Download(context.Background(), srv.URL+"/test.tgz", "")
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("exceeds maximum size")) {
		t.Errorf("expected max size error, got: %v", err)
	}
}

func TestDownload_NetworkError(t *testing.T) {
	_, err := Download(context.Background(), "http://127.0.0.1:0/nonexistent.tgz", "")
	if err == nil {
		t.Error("expected network error")
	}
}

func TestIsJSFile_CJS(t *testing.T) {
	if !isJSFile("module.cjs") {
		t.Error("expected .cjs to be recognized as JS")
	}
	if !isJSFile("module.mts") {
		t.Error("expected .mts to be recognized as JS")
	}
	if !isJSFile("module.cts") {
		t.Error("expected .cts to be recognized as JS")
	}
}

func TestIsJSFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"index.js", true},
		{"lib/util.mjs", true},
		{"src/main.ts", true},
		{"readme.md", false},
		{"image.png", false},
		{"style.css", false},
	}

	for _, tt := range tests {
		got := isJSFile(tt.path)
		if got != tt.want {
			t.Errorf("isJSFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
