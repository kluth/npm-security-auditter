package analyzer

import (
	"fmt"
	"regexp"
)

// EnvFingerprintAnalyzer detects environment fingerprinting patterns where
// packages probe for CI/CD, cloud, VM, or container environments to
// selectively activate malicious payloads or evade sandboxes.
// Based on DONAPI (USENIX Security 2024) and Cycode research.
type EnvFingerprintAnalyzer struct{}

func NewEnvFingerprintAnalyzer() *EnvFingerprintAnalyzer {
	return &EnvFingerprintAnalyzer{}
}

func (a *EnvFingerprintAnalyzer) Name() string {
	return "env-fingerprinting"
}

var (
	// CI/CD environment probing
	ciEnvPattern = regexp.MustCompile(`(?i)process\.env\.\s*(?:CI|GITHUB_ACTIONS|GITHUB_TOKEN|GITLAB_CI|JENKINS_URL|TRAVIS|CIRCLECI|CODEBUILD|BITBUCKET_PIPELINE|AZURE_PIPELINE|TEAMCITY|BUILDKITE)`)

	// Cloud environment probing
	cloudEnvPattern = regexp.MustCompile(`(?i)process\.env\.\s*(?:AWS_LAMBDA|AWS_ACCESS_KEY|AWS_SECRET|GOOGLE_CLOUD|GCLOUD|GCP_PROJECT|AZURE_CLIENT|AZURE_TENANT|AZURE_SUBSCRIPTION|KUBERNETES_SERVICE|K8S_)`)

	// VM/sandbox detection via hardware checks
	vmDetectionPattern = regexp.MustCompile(`(?i)(?:os\.cpus\(\)\.length|os\.totalmem\(\)|os\.freemem\(\))\s*[<>]=?\s*\d+`)

	// Container detection
	containerDetectionPattern = regexp.MustCompile(`(?i)(?:\.dockerenv|/proc/1/cgroup|/proc/self/cgroup|DOCKER_HOST|KUBERNETES_SERVICE_HOST)`)

	// Multi-signal OS fingerprinting (3+ signals together)
	osHostnamePattern    = regexp.MustCompile(`(?i)os\.hostname\(\)`)
	osUserInfoPattern    = regexp.MustCompile(`(?i)os\.userInfo\(\)`)
	osNetworkPattern     = regexp.MustCompile(`(?i)os\.networkInterfaces\(\)`)
	osPlatformArchPattern = regexp.MustCompile(`(?i)os\.(?:platform|arch)\(\)`)
)

func (a *EnvFingerprintAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	// CI/CD environment probing
	if ciEnvPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "CI/CD environment fingerprinting",
			Description: fmt.Sprintf("File %q checks for CI/CD environment variables. This is used to selectively activate payloads in build pipelines where tokens and secrets are available.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "CI/CD-targeted attacks check for build environment:\n" +
				"    if (process.env.GITHUB_ACTIONS) {\n" +
				"      steal(process.env.GITHUB_TOKEN);\n" +
				"    }\n" +
				"    Build environments have access to deployment keys, npm tokens, etc.",
			Remediation: "Investigate why this package needs to detect CI/CD. Legitimate packages rarely check for CI-specific variables.",
		})
	}

	// Cloud environment probing
	if cloudEnvPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Cloud environment fingerprinting",
			Description: fmt.Sprintf("File %q probes for cloud provider environment variables (AWS, GCP, Azure). This may target cloud credentials.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Cloud-targeted credential theft:\n" +
				"    const key = process.env.AWS_ACCESS_KEY_ID;\n" +
				"    const secret = process.env.AWS_SECRET_ACCESS_KEY;\n" +
				"    Stolen cloud credentials enable crypto-mining, data theft, etc.",
			Remediation: "Verify the package legitimately needs cloud SDK access. Most packages should not read cloud credentials.",
		})
	}

	// VM/sandbox detection
	if vmDetectionPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "VM/sandbox evasion detection",
			Description: fmt.Sprintf("File %q checks hardware specs (CPU count, memory) to detect virtual machines or sandboxes. Malware uses this to avoid analysis.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Sandbox evasion via hardware fingerprinting:\n" +
				"    if (os.cpus().length <= 1 || os.totalmem() < 2GB) {\n" +
				"      process.exit(0); // Skip payload in sandbox\n" +
				"    }\n" +
				"    Malware aborts in analysis environments to avoid detection.",
			Remediation: "Hardware specification checks in npm packages are highly suspicious. Investigate the purpose of this check.",
		})
	}

	// Container detection
	if containerDetectionPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Container environment detection",
			Description: fmt.Sprintf("File %q checks for Docker/Kubernetes indicators. This may be used to modify behavior in container environments.", filename),
			Severity:    SeverityMedium,
			ExploitExample: "Container detection enables environment-specific attacks:\n" +
				"    if (fs.existsSync('/.dockerenv')) {\n" +
				"      // Container breakout or different payload\n" +
				"    }\n" +
				"    Attackers may use different payloads inside vs outside containers.",
			Remediation: "Verify the package has a legitimate reason to detect container environments.",
		})
	}

	// Multi-signal OS fingerprinting
	fingerprintSignals := 0
	if osHostnamePattern.MatchString(content) {
		fingerprintSignals++
	}
	if osUserInfoPattern.MatchString(content) {
		fingerprintSignals++
	}
	if osNetworkPattern.MatchString(content) {
		fingerprintSignals++
	}
	if osPlatformArchPattern.MatchString(content) {
		fingerprintSignals++
	}

	if fingerprintSignals >= 3 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Extensive system fingerprinting",
			Description: fmt.Sprintf("File %q collects %d types of system information (hostname, user, network, platform). This level of system reconnaissance is suspicious.", filename, fingerprintSignals),
			Severity:    SeverityHigh,
			ExploitExample: "System fingerprinting creates unique victim profiles:\n" +
				"    const profile = {\n" +
				"      hostname: os.hostname(),\n" +
				"      user: os.userInfo().username,\n" +
				"      network: os.networkInterfaces(),\n" +
				"    };\n" +
				"    Sent to C2 server for targeted follow-up attacks.",
			Remediation: "Packages collecting multiple OS identifiers are likely conducting system reconnaissance.",
		})
	}

	return findings
}
