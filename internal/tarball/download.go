package tarball

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxTotalSize = 100 * 1024 * 1024 // 100MB
	maxFileSize  = 10 * 1024 * 1024  // 10MB per file
	maxFiles     = 10000
)

// FileEntry represents a single extracted file.
type FileEntry struct {
	Path string // relative path within the package
	Size int64
	IsJS bool
}

// ExtractedPackage holds the result of downloading and extracting a tarball.
type ExtractedPackage struct {
	Dir         string      // temporary directory root
	Files       []FileEntry // all extracted files
	PackageJSON []byte      // raw package.json contents, if found
}

// Cleanup removes the temporary directory.
func (ep *ExtractedPackage) Cleanup() {
	if ep != nil && ep.Dir != "" {
		os.RemoveAll(ep.Dir)
	}
}

// Download fetches the tarball at the given URL, verifies its SHA-1 against
// expectedShasum, and extracts it into a temporary directory. The caller must
// call Cleanup() on the returned ExtractedPackage when done.
func Download(ctx context.Context, tarballURL, expectedShasum string) (*ExtractedPackage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading tarball: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tarball download returned status %d", resp.StatusCode)
	}

	// Tee the response body through a SHA-1 hasher.
	hasher := sha1.New()
	limitedBody := io.LimitReader(resp.Body, maxTotalSize+1)
	reader := io.TeeReader(limitedBody, hasher)

	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tmpDir, err := os.MkdirTemp("", "auditter-tarball-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}

	ep := &ExtractedPackage{Dir: tmpDir}

	tr := tar.NewReader(gz)
	var totalSize int64
	fileCount := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			ep.Cleanup()
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		// Only process regular files.
		if header.Typeflag != tar.TypeReg {
			continue
		}

		fileCount++
		if fileCount > maxFiles {
			ep.Cleanup()
			return nil, fmt.Errorf("tarball exceeds maximum file count (%d)", maxFiles)
		}

		if header.Size > maxFileSize {
			ep.Cleanup()
			return nil, fmt.Errorf("file %q exceeds maximum size (%d bytes)", header.Name, maxFileSize)
		}

		totalSize += header.Size
		if totalSize > maxTotalSize {
			ep.Cleanup()
			return nil, fmt.Errorf("tarball exceeds maximum total size (%d bytes)", maxTotalSize)
		}

		// Sanitize the path: strip the leading "package/" prefix that npm
		// tarballs use, and reject any traversal attempts.
		cleanName := sanitizePath(header.Name)
		if cleanName == "" {
			continue
		}

		destPath := filepath.Join(tmpDir, cleanName)

		// Ensure destination is within tmpDir (path traversal guard).
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(tmpDir)+string(os.PathSeparator)) {
			ep.Cleanup()
			return nil, fmt.Errorf("path traversal detected: %q", header.Name)
		}

		// Create parent directories.
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			ep.Cleanup()
			return nil, fmt.Errorf("creating directory for %q: %w", cleanName, err)
		}

		f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			ep.Cleanup()
			return nil, fmt.Errorf("creating file %q: %w", cleanName, err)
		}

		written, err := io.Copy(f, io.LimitReader(tr, maxFileSize))
		f.Close()
		if err != nil {
			ep.Cleanup()
			return nil, fmt.Errorf("writing file %q: %w", cleanName, err)
		}

		isJS := isJSFile(cleanName)
		ep.Files = append(ep.Files, FileEntry{
			Path: cleanName,
			Size: written,
			IsJS: isJS,
		})

		// Capture package.json from the root of the package.
		if cleanName == "package.json" {
			data, err := os.ReadFile(destPath)
			if err == nil {
				ep.PackageJSON = data
			}
		}
	}

	// Drain any remaining data so the hasher sees everything.
	io.Copy(io.Discard, reader)

	// Verify shasum.
	actualShasum := hex.EncodeToString(hasher.Sum(nil))
	if expectedShasum != "" && actualShasum != expectedShasum {
		ep.Cleanup()
		return nil, &ShasumMismatchError{
			Expected: expectedShasum,
			Actual:   actualShasum,
		}
	}

	return ep, nil
}

// ShasumMismatchError is returned when the tarball shasum doesn't match.
type ShasumMismatchError struct {
	Expected string
	Actual   string
}

func (e *ShasumMismatchError) Error() string {
	return fmt.Sprintf("shasum mismatch: expected %s, got %s", e.Expected, e.Actual)
}

// sanitizePath cleans a tar entry path. npm tarballs typically have a
// "package/" prefix; we strip it. Paths with ".." components are rejected.
func sanitizePath(name string) string {
	// Strip leading "package/" prefix (standard npm tarball layout).
	name = strings.TrimPrefix(name, "package/")

	// Clean the path.
	name = filepath.Clean(name)

	// Reject empty, absolute, or traversal paths.
	if name == "." || name == "" || filepath.IsAbs(name) || strings.Contains(name, "..") {
		return ""
	}

	return name
}

// isJSFile returns true for JavaScript/TypeScript source files.
func isJSFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
		return true
	}
	return false
}
