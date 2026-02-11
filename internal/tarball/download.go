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

	hasher := sha1.New()
	limitedBody := io.LimitReader(resp.Body, maxTotalSize+1)
	reader := io.TeeReader(limitedBody, hasher)

	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	ep, err := extractTar(gz)
	if err != nil {
		return nil, err
	}

	// Drain any remaining data so the hasher sees everything.
	io.Copy(io.Discard, reader)

	actualShasum := hex.EncodeToString(hasher.Sum(nil))
	if expectedShasum != "" && actualShasum != expectedShasum {
		ep.Cleanup()
		return nil, &ShasumMismatchError{Expected: expectedShasum, Actual: actualShasum}
	}

	return ep, nil
}

func extractTar(gz io.Reader) (*ExtractedPackage, error) {
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

		if header.Typeflag != tar.TypeReg {
			continue
		}

		fileCount++
		if err := validateLimits(fileCount, header.Size, totalSize); err != nil {
			ep.Cleanup()
			return nil, err
		}
		totalSize += header.Size

		cleanName := sanitizePath(header.Name)
		if cleanName == "" {
			continue
		}

		if err := extractFile(ep, tr, tmpDir, cleanName); err != nil {
			ep.Cleanup()
			return nil, err
		}
	}

	return ep, nil
}

func validateLimits(fileCount int, fileSize, totalSize int64) error {
	if fileCount > maxFiles {
		return fmt.Errorf("tarball exceeds maximum file count (%d)", maxFiles)
	}
	if fileSize > maxFileSize {
		return fmt.Errorf("file exceeds maximum size (%d bytes)", maxFileSize)
	}
	if totalSize+fileSize > maxTotalSize {
		return fmt.Errorf("tarball exceeds maximum total size (%d bytes)", maxTotalSize)
	}
	return nil
}

func extractFile(ep *ExtractedPackage, tr *tar.Reader, tmpDir, cleanName string) error {
	destPath := filepath.Join(tmpDir, cleanName)

	if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(tmpDir)+string(os.PathSeparator)) {
		return fmt.Errorf("path traversal detected: %q", cleanName)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("creating directory for %q: %w", cleanName, err)
	}

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", cleanName, err)
	}

	written, err := io.Copy(f, io.LimitReader(tr, maxFileSize))
	f.Close()
	if err != nil {
		return fmt.Errorf("writing file %q: %w", cleanName, err)
	}

	ep.Files = append(ep.Files, FileEntry{
		Path: cleanName,
		Size: written,
		IsJS: isJSFile(cleanName),
	})

	if cleanName == "package.json" {
		data, err := os.ReadFile(destPath)
		if err == nil {
			ep.PackageJSON = data
		}
	}

	return nil
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
