package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

// VersionAnomalyAnalyzer detects suspicious version publishing patterns
// such as rapid publishing, large version jumps, dormant package revivals,
// and unpublished version evidence.
type VersionAnomalyAnalyzer struct{}

func NewVersionAnomalyAnalyzer() *VersionAnomalyAnalyzer {
	return &VersionAnomalyAnalyzer{}
}

func (a *VersionAnomalyAnalyzer) Name() string {
	return "version-anomalies"
}

func (a *VersionAnomalyAnalyzer) Analyze(ctx context.Context, pkg *registry.PackageMetadata, version *registry.PackageVersion) ([]Finding, error) {
	var findings []Finding

	if len(pkg.Time) == 0 {
		return nil, nil
	}

	// Collect version timestamps (excluding "created" and "modified")
	type versionTime struct {
		version string
		time    time.Time
	}
	var versionTimes []versionTime
	for v, t := range pkg.Time {
		if v == "created" || v == "modified" {
			continue
		}
		versionTimes = append(versionTimes, versionTime{v, t})
	}

	sort.Slice(versionTimes, func(i, j int) bool {
		return versionTimes[i].time.Before(versionTimes[j].time)
	})

	// 1. Single version 0.0.1 - common in malware
	if len(pkg.Versions) == 1 {
		for v := range pkg.Versions {
			if v == "0.0.1" || v == "0.0.0" || v == "1.0.0" {
				created, ok := pkg.Time["created"]
				age := ""
				if ok {
					age = fmt.Sprintf(" (created %s ago)", time.Since(created).Round(time.Hour))
				}
				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       fmt.Sprintf("Single version package (%s)", v),
					Description: fmt.Sprintf("Package has only one version%s. Single-version packages are commonly used in supply chain attacks.", age),
					Severity:    SeverityMedium,
					ExploitExample: "Malicious packages are typically published as a single version:\n" +
						"    - Attacker creates package, adds malicious postinstall\n" +
						"    - Publishes v0.0.1 or v1.0.0\n" +
						"    - Waits for victims via typosquatting or dependency confusion\n" +
						"    - 73% of malicious npm packages have only 1 version (2024 data)",
					Remediation: "Be cautious with single-version packages. Check the package age, maintainer, and code quality.",
				})
			}
		}
	}

	// 2. Rapid publishing - many versions in short time
	if len(versionTimes) >= 5 {
		last5 := versionTimes[len(versionTimes)-5:]
		duration := last5[4].time.Sub(last5[0].time)
		if duration < 24*time.Hour {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Rapid version publishing",
				Description: fmt.Sprintf("5 versions published within %s. This is unusually fast and may indicate automated malicious publishing.", duration.Round(time.Minute)),
				Severity:    SeverityMedium,
				ExploitExample: "Rapid publishing patterns indicate automated attacks:\n" +
					"    - Attacker scripts publish many typosquats quickly\n" +
					"    - Each version may target different payloads\n" +
					"    - Speed suggests automation, not human development",
				Remediation: "Investigate the version history. Legitimate packages rarely publish 5+ versions in under 24 hours.",
			})
		}
	}

	// 3. Major version jump
	if len(versionTimes) >= 2 {
		for i := 1; i < len(versionTimes); i++ {
			prevMajor := parseMajorVersion(versionTimes[i-1].version)
			currMajor := parseMajorVersion(versionTimes[i].version)
			if prevMajor >= 0 && currMajor >= 0 && currMajor-prevMajor > 5 {
				findings = append(findings, Finding{
					Analyzer:    a.Name(),
					Title:       fmt.Sprintf("Suspicious version jump: %s -> %s", versionTimes[i-1].version, versionTimes[i].version),
					Description: fmt.Sprintf("Major version jumped from %d to %d, a gap of %d major versions.", prevMajor, currMajor, currMajor-prevMajor),
					Severity:    SeverityMedium,
					ExploitExample: "Large version jumps can indicate package takeover:\n" +
						"    - Attacker gains access to dormant package\n" +
						"    - Publishes a high version to ensure it's installed as 'latest'\n" +
						"    - The large gap is atypical of normal development",
					Remediation: "Check if the maintainer changed around this version jump. Compare code between versions.",
				})
			}
		}
	}

	// 4. Dormant package revival
	if len(versionTimes) >= 2 {
		last := versionTimes[len(versionTimes)-1]
		prev := versionTimes[len(versionTimes)-2]
		gap := last.time.Sub(prev.time)
		if gap > 365*24*time.Hour {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("Dormant package revived after %d days", int(gap.Hours()/24)),
				Description: fmt.Sprintf("Package had no updates for %s, then suddenly published %s. This pattern is seen in account takeovers.", gap.Round(24*time.Hour), last.version),
				Severity:    SeverityHigh,
				ExploitExample: "Dormant package revival is a key attack vector:\n" +
					"    event-stream attack (2018):\n" +
					"    1. Original maintainer abandoned the package\n" +
					"    2. Attacker volunteered to 'help maintain' it\n" +
					"    3. Published malicious version after gaining access\n" +
					"    4. Affected millions of downstream projects",
				Remediation: "Verify the maintainer is still the same. Compare code carefully between the old and new versions.",
			})
		}
	}

	// 5. Unpublished versions (versions in time map but not in versions map)
	unpublishedCount := 0
	for v := range pkg.Time {
		if v == "created" || v == "modified" {
			continue
		}
		if _, exists := pkg.Versions[v]; !exists {
			unpublishedCount++
		}
	}
	if unpublishedCount >= 2 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       fmt.Sprintf("Unpublished versions detected (%d)", unpublishedCount),
			Description: fmt.Sprintf("%d versions were published and then removed. This may indicate the author tried to hide malicious releases.", unpublishedCount),
			Severity:    SeverityMedium,
			ExploitExample: "Unpublishing versions is suspicious:\n" +
				"    - Attacker publishes malicious version\n" +
				"    - After infection, unpublishes to remove evidence\n" +
				"    - npm retains time records even after unpublish\n" +
				"    - Affected users still have the malicious version cached",
			Remediation: "Check what happened in the unpublished versions. They may have contained malicious code that was caught.",
		})
	}

	return findings, nil
}

// parseMajorVersion extracts the major version number from a semver string.
func parseMajorVersion(version string) int {
	parts := strings.SplitN(version, ".", 2)
	if len(parts) == 0 {
		return -1
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return -1
	}
	return major
}
