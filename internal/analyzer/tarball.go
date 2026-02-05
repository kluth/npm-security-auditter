package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/tarball"
)

// Patterns that indicate a file is in a minified/distribution directory.
var minifiedPathPatterns = []string{
	"/dist/",
	"/build/",
	"/bundle/",
	"/lib/",
	"/umd/",
	"/esm/",
	"/cjs/",
	"/fesm",  // Angular flat ESM
	".min.",
	".bundle.",
	".prod.",
	"-min.",
	"-bundle.",
}

// sourceMappingURLPattern detects source map references in minified files.
var sourceMappingURLPattern = regexp.MustCompile(`//[#@]\s*sourceMappingURL=`)

// isLikelyMinifiedPath checks if the file path suggests minified/bundled content.
func isLikelyMinifiedPath(path string) bool {
	pathLower := strings.ToLower(path)
	for _, pattern := range minifiedPathPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

// isLikelyMinifiedContent checks content characteristics that suggest minification.
func isLikelyMinifiedContent(content []byte) bool {
	if len(content) < 500 {
		return false
	}

	// Check for source mapping URL (strong indicator of minified code)
	if sourceMappingURLPattern.Match(content) {
		return true
	}

	// Check average line length
	lines := bytes.Split(content, []byte("\n"))
	if len(lines) == 0 {
		return false
	}

	totalLen := 0
	for _, line := range lines {
		totalLen += len(line)
	}
	avgLineLen := totalLen / len(lines)

	// Very long average line length suggests minification
	if avgLineLen > 500 {
		return true
	}

	// Check for common minifier patterns
	minifierPatterns := [][]byte{
		[]byte("!function("),
		[]byte("(function("),
		[]byte("Object.defineProperty("),
		[]byte("__webpack_require__"),
		[]byte("__esModule"),
	}

	for _, pattern := range minifierPatterns {
		if bytes.Contains(content[:minInt(1000, len(content))], pattern) {
			return true
		}
	}

	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TarballAnalyzer performs deep content analysis of extracted package tarballs.
type TarballAnalyzer struct{}

func NewTarballAnalyzer() *TarballAnalyzer {
	return &TarballAnalyzer{}
}

func (a *TarballAnalyzer) Name() string {
	return "tarball-analysis"
}

func (a *TarballAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	if version.Dist.Tarball == "" {
		return nil, fmt.Errorf("no tarball URL in package metadata")
	}

	ep, err := tarball.Download(ctx, version.Dist.Tarball, version.Dist.Shasum)
	if err != nil {
		var mismatch *tarball.ShasumMismatchError
		if errors.As(err, &mismatch) {
			return []Finding{{
				Analyzer:    a.Name(),
				Title:       "Tarball SHA-1 mismatch",
				Description: fmt.Sprintf("The tarball checksum does not match the registry value. Expected %s, got %s. This could indicate tampering.", mismatch.Expected, mismatch.Actual),
				Severity:    SeverityCritical,
			}}, nil
		}
		return nil, fmt.Errorf("downloading tarball: %w", err)
	}
	defer ep.Cleanup()

	var findings []Finding

	findings = append(findings, a.scanJSFiles(ep)...)
	findings = append(findings, a.detectObfuscation(ep)...)
	findings = append(findings, a.findHiddenFiles(ep)...)
	findings = append(findings, a.detectBinaries(ep)...)
	findings = append(findings, a.findEncodedPayloads(ep)...)
	findings = append(findings, a.comparePackageJSON(ep, version)...)
	findings = append(findings, a.entropyAnalysis(ep)...)
	findings = append(findings, a.findCryptoWallets(ep)...)
	findings = append(findings, a.checkMalwareSignatures(ep)...)
	findings = append(findings, a.checkLargeFiles(ep)...)
	findings = append(findings, a.detectNativeBuilds(ep)...)

	// Minified only check
	minA := NewMinifiedOnlyAnalyzer()
	minFindings, _ := minA.AnalyzePackage(ctx, ep)
	findings = append(findings, minFindings...)

	// Dangerous extensions check
	extA := NewDangerousExtensionAnalyzer()
	extFindings, _ := extA.AnalyzePackage(ctx, ep)
	findings = append(findings, extFindings...)

	// Lockfile integrity check
	lockA := NewLockfileAnalyzer()
	lockFindings, _ := lockA.AnalyzePackage(ctx, ep)
	findings = append(findings, lockFindings...)

	return findings, nil
}

func (a *TarballAnalyzer) detectNativeBuilds(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	for _, f := range ep.Files {
		if filepath.Base(f.Path) == "binding.gyp" {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Native build configuration (binding.gyp)",
				Description: fmt.Sprintf("File %q indicates this package contains native C/C++ components. Native builds have a larger attack surface and can bypass many JS-level security monitors.", f.Path),
				Severity:    SeverityMedium,
			})
		}
	}
	return findings
}

func (a *TarballAnalyzer) checkLargeFiles(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	for _, f := range ep.Files {
		// Flag files larger than 1MB
		if f.Size > 1024*1024 {
			severity := SeverityLow
			if f.IsJS {
				severity = SeverityMedium
			}
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Large file detected",
				Description: fmt.Sprintf("File %q is unusually large (%.2f MB).", f.Path, float64(f.Size)/(1024*1024)),
				Severity:    severity,
				ExploitExample: "Large files can be used to hide malicious code or data:\n" +
					"    - Attackers may append malicious payloads to large, legitimate-looking assets\n" +
					"    - Large JS files are difficult to review and can hide complex obfuscated code\n" +
					"    - This could also indicate a bloated package that impacts build performance",
				Remediation: "Manually inspect the content of large files to ensure they do not contain hidden payloads or unnecessary data.",
			})
		}
	}
	return findings
}

func (a *TarballAnalyzer) scanJSFiles(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	envA := NewEnvAnalyzer()
	telA := NewTelemetryAnalyzer()
	sideA := NewSideEffectAnalyzer()
	netA := NewPrivateNetworkAnalyzer()
	urlA := NewSuspiciousURLAnalyzer()

	for _, f := range ep.Files {
		if !f.IsJS {
			continue
		}
		contentBytes, err := os.ReadFile(filepath.Join(ep.Dir, f.Path))
		if err != nil {
			continue
		}
		content := string(contentBytes)

		// Env variables
		findings = append(findings, envA.scanContent(content, f.Path)...)
		// Telemetry
		findings = append(findings, telA.scanContent(content, f.Path)...)
		// Side effects
		findings = append(findings, sideA.scanContent(content, f.Path)...)
		// Network
		findings = append(findings, netA.scanContent(content, f.Path)...)
		// URLs
		findings = append(findings, urlA.scanContent(content, f.Path)...)

		for _, pat := range maliciousJSPatterns {
			if pat.Pattern.Match(contentBytes) {
				findings = append(findings, Finding{
					Analyzer:       "tarball-analysis",
					Title:          fmt.Sprintf("Suspicious pattern: %s", pat.Name),
					Description:    fmt.Sprintf("File %q contains a suspicious pattern (%s) that may indicate malicious behavior.", f.Path, pat.Name),
					Severity:       pat.Severity,
					ExploitExample: pat.ExploitExample,
					Remediation:    pat.Remediation,
				})
			}
		}
	}
	return findings
}

func (a *TarballAnalyzer) detectObfuscation(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	for _, f := range ep.Files {
		if !f.IsJS {
			continue
		}
		content, err := os.ReadFile(filepath.Join(ep.Dir, f.Path))
		if err != nil {
			continue
		}

		isMinified := isLikelyMinifiedPath(f.Path) || isLikelyMinifiedContent(content)

		lines := bytes.Split(content, []byte("\n"))
		if len(lines) == 0 {
			continue
		}

		// Check average line length.
		totalLen := 0
		for _, line := range lines {
			totalLen += len(line)
		}
		avgLineLen := totalLen / len(lines)

		// For minified files, only flag extremely long lines (likely packed/obfuscated)
		lineThreshold := 5000
		if isMinified {
			lineThreshold = 50000 // Much higher threshold for known minified files
		}

		if avgLineLen > lineThreshold {
			severity := SeverityMedium
			desc := fmt.Sprintf("File %q has an average line length of %d characters, which suggests obfuscation or suspicious minification.", f.Path, avgLineLen)
			if isMinified {
				severity = SeverityLow
				desc += " This is a distribution file, so long lines are expected from minification."
			}
			findings = append(findings, Finding{
				Analyzer:    "tarball-analysis",
				Title:       "Extremely long lines (likely minified/obfuscated)",
				Description: desc,
				Severity:    severity,
			})
		}

		// Skip non-alphanumeric ratio check entirely for minified files.
		// Minified code naturally has high punctuation density.
		if isMinified {
			continue
		}

		// Check non-alphanumeric ratio.
		if len(content) > 100 {
			nonAlpha := 0
			for _, b := range content {
				if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == ' ' || b == '\n' || b == '\t') {
					nonAlpha++
				}
			}
			ratio := float64(nonAlpha) / float64(len(content))
			if ratio > 0.5 {
				findings = append(findings, Finding{
					Analyzer:    "tarball-analysis",
					Title:       "High non-alphanumeric ratio",
					Description: fmt.Sprintf("File %q has a non-alphanumeric character ratio of %.2f, suggesting encoded or obfuscated content.", f.Path, ratio),
					Severity:    SeverityMedium,
				})
			}
		}
	}
	return findings
}

func (a *TarballAnalyzer) findHiddenFiles(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	for _, f := range ep.Files {
		base := filepath.Base(f.Path)
		dir := filepath.Dir(f.Path)

		// Check the filename itself.
		if hiddenFileNames[base] {
			findings = append(findings, Finding{
				Analyzer:    "tarball-analysis",
				Title:       "Hidden/sensitive file in package",
				Description: fmt.Sprintf("File %q is a sensitive file that should not be included in a published package.", f.Path),
				Severity:    SeverityHigh,
			})
		}

		// Check directory components.
		for _, part := range strings.Split(dir, string(os.PathSeparator)) {
			if hiddenFileNames[part] {
				findings = append(findings, Finding{
					Analyzer:    "tarball-analysis",
					Title:       "Sensitive directory in package",
					Description: fmt.Sprintf("File %q is inside a sensitive directory (%s) that should not be included.", f.Path, part),
					Severity:    SeverityHigh,
				})
				break
			}
		}
	}
	return findings
}

func (a *TarballAnalyzer) detectBinaries(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	for _, f := range ep.Files {
		// Magic bytes check only (extensions handled by DangerousExtensionAnalyzer)
		content, err := readFileHead(filepath.Join(ep.Dir, f.Path), 8)
		if err != nil || len(content) < 2 {
			continue
		}

		for _, magic := range binaryMagicBytes {
			if len(content) >= len(magic.Magic) && bytes.Equal(content[:len(magic.Magic)], magic.Magic) {
				findings = append(findings, Finding{
					Analyzer:    "tarball-analysis",
					Title:       fmt.Sprintf("Binary detected: %s", magic.Name),
					Description: fmt.Sprintf("File %q contains magic bytes for %s. Compiled binaries in npm packages are suspicious.", f.Path, magic.Name),
					Severity:    SeverityHigh,
				})
				break
			}
		}
	}
	return findings
}

// isLikelyDataFile checks if a file appears to contain legitimate data (Unicode tables, etc.)
func isLikelyDataFile(path string, content []byte) bool {
	pathLower := strings.ToLower(path)

	// Files with these patterns are often data files, not code
	dataPatterns := []string{
		"unicode", "char", "word", "emoji", "symbol",
		"locale", "i18n", "l10n", "lang", "language",
		"encoding", "codec", "charset",
		"data", "table", "map", "dict",
	}
	for _, pattern := range dataPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}

	// Check for array/object literals with many Unicode escapes (data files)
	if bytes.Count(content, []byte("\\u")) > 50 {
		return true
	}

	// Check for large array literals (common in data files)
	if bytes.Count(content, []byte(",")) > 100 && bytes.Count(content, []byte("[")) > 0 {
		return true
	}

	return false
}

func (a *TarballAnalyzer) findEncodedPayloads(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	// Only scan JS/TS files for encoded payloads.
	b64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	for _, f := range ep.Files {
		if !f.IsJS {
			continue
		}
		content, err := os.ReadFile(filepath.Join(ep.Dir, f.Path))
		if err != nil {
			continue
		}

		isMinified := isLikelyMinifiedPath(f.Path) || isLikelyMinifiedContent(content)
		isDataFile := isLikelyDataFile(f.Path, content)

		// Skip entropy checks entirely for data files - they naturally have high entropy
		if isDataFile {
			continue
		}

		// Look for long base64 strings.
		// Use higher threshold for minified files since they often contain encoded assets.
		b64Threshold := 100
		if isMinified {
			b64Threshold = 500 // Much higher for dist files
		}

		inB64 := 0
		for _, b := range content {
			if strings.ContainsRune(b64Chars, rune(b)) {
				inB64++
			} else {
				if inB64 > b64Threshold {
					severity := SeverityMedium
					desc := fmt.Sprintf("File %q contains a base64-like string of %d characters, which may be an encoded payload.", f.Path, inB64)
					if isMinified {
						severity = SeverityLow
						desc += " This appears to be a minified distribution file where base64-encoded assets (fonts, images) are common."
					}
					findings = append(findings, Finding{
						Analyzer:    "tarball-analysis",
						Title:       "Long base64-encoded string",
						Description: desc,
						Severity:    severity,
					})
					break // one finding per file is enough
				}
				inB64 = 0
			}
		}

		// Compute Shannon entropy on chunks.
		// Use much higher threshold for minified files since they naturally have high entropy.
		if len(content) > 256 {
			entropy := shannonEntropy(content)
			entropyThreshold := 5.5 // High threshold - normal code rarely exceeds this
			if isMinified {
				entropyThreshold = 6.5 // Much higher for dist files
			}

			if entropy > entropyThreshold {
				severity := SeverityLow
				desc := fmt.Sprintf("File %q contains highly randomized data (complexity score: %.2f), which often indicates encoded, encrypted, or obfuscated payloads.", f.Path, entropy)
				if isMinified {
					desc += " This appears to be a minified distribution file. High entropy is expected and usually not a security concern."
				}
				findings = append(findings, Finding{
					Analyzer:    "tarball-analysis",
					Title:       "High entropy content",
					Description: desc,
					Severity:    severity,
				})
			}
		}
	}
	return findings
}

func (a *TarballAnalyzer) comparePackageJSON(ep *tarball.ExtractedPackage, version *registry.PackageVersion) []Finding {
	if ep.PackageJSON == nil {
		return nil
	}

	var findings []Finding
	var tarballPkg struct {
		Name         string            `json:"name"`
		Version      string            `json:"version"`
		Scripts      map[string]string `json:"scripts"`
		Dependencies map[string]string `json:"dependencies"`
	}

	if err := json.Unmarshal(ep.PackageJSON, &tarballPkg); err != nil {
		return nil
	}

	// Name mismatch.
	if tarballPkg.Name != "" && tarballPkg.Name != version.Name {
		findings = append(findings, Finding{
			Analyzer:    "tarball-analysis",
			Title:       "Package name mismatch",
			Description: fmt.Sprintf("Tarball package.json name is %q but registry says %q. This is highly suspicious.", tarballPkg.Name, version.Name),
			Severity:    SeverityCritical,
		})
	}

	// Check for extra scripts in tarball not in registry.
	dangerousScripts := []string{"preinstall", "install", "postinstall", "preuninstall", "postuninstall"}
	for _, scriptName := range dangerousScripts {
		tarballScript, inTarball := tarballPkg.Scripts[scriptName]
		_, inRegistry := version.Scripts[scriptName]
		if inTarball && !inRegistry {
			findings = append(findings, Finding{
				Analyzer:       "tarball-analysis",
				Title:          "Hidden install script in tarball",
				Description:    fmt.Sprintf("The tarball contains a %q script (%s) not visible in registry metadata.", scriptName, tarballScript),
				Severity:       SeverityCritical,
				ExploitExample: fmt.Sprintf("The script %q runs: %s", scriptName, tarballScript),
			})
		}
	}

	// Extra dependencies in tarball.
	for dep := range tarballPkg.Dependencies {
		if _, ok := version.Dependencies[dep]; !ok {
			findings = append(findings, Finding{
				Analyzer:    "tarball-analysis",
				Title:       "Hidden dependency in tarball",
				Description: fmt.Sprintf("Tarball package.json lists dependency %q not in registry metadata.", dep),
				Severity:    SeverityHigh,
			})
		}
	}

	return findings
}

func (a *TarballAnalyzer) entropyAnalysis(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	for _, f := range ep.Files {
		if !f.IsJS || f.Size < 256 {
			continue
		}
		content, err := os.ReadFile(filepath.Join(ep.Dir, f.Path))
		if err != nil {
			continue
		}

		isMinified := isLikelyMinifiedPath(f.Path) || isLikelyMinifiedContent(content)

		// Skip HIGH severity entropy findings for minified files entirely.
		// They naturally have high entropy due to variable name mangling, etc.
		if isMinified {
			continue
		}

		entropy := shannonEntropy(content)
		if entropy > 5.5 {
			findings = append(findings, Finding{
				Analyzer:    "tarball-analysis",
				Title:       "Extremely high entropy content",
				Description: fmt.Sprintf("File %q contains extremely randomized data (complexity score: %.2f), which is a strong indicator of obfuscated or encrypted malicious code.", f.Path, entropy),
				Severity:    SeverityHigh,
			})
		}
	}
	return findings
}

func (a *TarballAnalyzer) findCryptoWallets(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	for _, f := range ep.Files {
		if !f.IsJS {
			continue
		}
		content, err := os.ReadFile(filepath.Join(ep.Dir, f.Path))
		if err != nil {
			continue
		}

		for _, pat := range cryptoWalletPatterns {
			if pat.Pattern.Match(content) {
				findings = append(findings, Finding{
					Analyzer:    "tarball-analysis",
					Title:       fmt.Sprintf("Cryptocurrency address found: %s", pat.Name),
					Description: fmt.Sprintf("File %q contains what appears to be a %s. This may indicate cryptojacking or unauthorized mining.", f.Path, pat.Name),
					Severity:    SeverityHigh,
				})
			}
		}
	}
	return findings
}

func (a *TarballAnalyzer) checkMalwareSignatures(ep *tarball.ExtractedPackage) []Finding {
	var findings []Finding
	for _, f := range ep.Files {
		content, err := os.ReadFile(filepath.Join(ep.Dir, f.Path))
		if err != nil {
			continue
		}

		for _, sig := range knownMalwareSignatures {
			if bytes.Contains(content, sig.Signature) {
				findings = append(findings, Finding{
					Analyzer:    "tarball-analysis",
					Title:       fmt.Sprintf("Known malware signature: %s", sig.Name),
					Description: fmt.Sprintf("File %q matches a known malware signature (%s). This package may be compromised.", f.Path, sig.Name),
					Severity:    SeverityCritical,
				})
			}
		}
	}
	return findings
}

// shannonEntropy computes the Shannon entropy of a byte slice in bits per byte.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}

	n := float64(len(data))
	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := count / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// readFileHead reads the first n bytes of a file.
func readFileHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, n)
	read, err := f.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:read], nil
}
