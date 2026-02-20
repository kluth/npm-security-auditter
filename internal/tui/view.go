package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var content string
	switch m.screen {
	case ScreenDashboard:
		content = m.viewDashboard()
	case ScreenMain:
		content = m.viewMain()
	case ScreenAuditPackage:
		content = m.viewAuditPackage()
	case ScreenAuditProject:
		content = m.viewAuditProject()
	case ScreenAuditNodeModules:
		content = m.viewAuditNodeModules()
	case ScreenAuditTop:
		content = m.viewAuditTop()
	case ScreenSettings:
		content = m.viewSettings()
	case ScreenThreatIntel:
		content = m.viewThreatIntel()
	case ScreenRunning:
		content = m.viewRunning()
	case ScreenSaveReport:
		content = m.viewSaveReport()
	default:
		content = m.viewDashboard()
	}

	// Compose with status bar
	statusBar := m.viewStatusBar()
	return lipgloss.JoinVertical(lipgloss.Left, content, statusBar)
}

func (m Model) viewStatusBar() string {
	var keys string
	switch m.screen {
	case ScreenDashboard:
		keys = "tab switch pane • ↑/↓ navigate • enter select/detail • s save • q quit"
	case ScreenMain:
		keys = "↑/↓ navigate • enter select • q quit"
	case ScreenAuditPackage, ScreenAuditProject, ScreenAuditNodeModules, ScreenAuditTop:
		keys = "enter submit • esc back"
	case ScreenSettings:
		keys = "tab/↓ next field • shift+tab/↑ prev • esc save & back"
	case ScreenThreatIntel:
		keys = "enter update • esc back"
	case ScreenRunning:
		keys = "please wait..."
	case ScreenSaveReport:
		keys = "enter save • esc cancel"
	default:
		keys = "tab switch pane • ↑/↓ navigate • enter select/detail • s save • q quit"
	}
	bar := StatusBarStyle.Width(m.width).Render(keys)
	return bar
}

func (m Model) viewDashboard() string {
	// Left Sidebar (Menu)
	menuStyle := PaneStyle
	if m.activePane == PaneMenu {
		menuStyle = FocusedPaneStyle
	}
	sidebarWidth := 30
	sidebar := menuStyle.Width(sidebarWidth).Height(m.height - 4).Render(m.mainMenu.View())

	// Right Content
	mainWidth := m.width - sidebarWidth - 4
	var rightPane string

	if m.results == nil {
		rightPane = lipgloss.Place(mainWidth, m.height-4, lipgloss.Center, lipgloss.Center,
			BoxStyle.Render(SubtitleStyle.Render("No audit results yet. Select an option from the menu to start.")))
	} else {
		// Summary (Top)
		summary := m.viewResultsSummary()
		summaryBox := BoxStyle.Width(mainWidth - 4).Render(summary)

		// Findings (Left bottom)
		findingsWidth := (mainWidth - 4) / 2
		findingsStyle := PaneStyle
		if m.activePane == PaneFindings {
			findingsStyle = FocusedPaneStyle
		}
		
		m.findingsList.SetSize(findingsWidth-2, m.height-14)
		findingsList := findingsStyle.Width(findingsWidth).Height(m.height - 12).Render(m.findingsList.View())

		// Detail (Right bottom)
		detailStyle := PaneStyle
		if m.activePane == PaneDetail {
			detailStyle = FocusedPaneStyle
		}
		m.detailView.Width = mainWidth - findingsWidth - 6
		m.detailView.Height = m.height - 14
		detailView := detailStyle.Width(mainWidth - findingsWidth - 4).Height(m.height - 12).Render(m.detailView.View())

		bottomPanes := lipgloss.JoinHorizontal(lipgloss.Top, findingsList, detailView)
		rightPane = lipgloss.JoinVertical(lipgloss.Left, summaryBox, bottomPanes)
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, sidebar, rightPane)
}

func (m Model) viewMain() string {
	return m.mainMenu.View()
}

func (m Model) viewAuditPackage() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Audit Package"))
	b.WriteString("\n\n")
	b.WriteString(InputLabelStyle.Render("Package name (optionally with @version):"))
	b.WriteString("\n")
	b.WriteString(InputStyle.Width(m.width - 6).Render(m.textInput.View()))
	b.WriteString("\n\n")
	b.WriteString(HelpStyle.Render("Examples: lodash, express@4.18.2, @babel/core"))
	return lipgloss.Place(m.width, m.height-2, lipgloss.Left, lipgloss.Top,
		lipgloss.NewStyle().Padding(1, 2).Render(b.String()))
}

func (m Model) viewAuditProject() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Audit Project"))
	b.WriteString("\n\n")
	b.WriteString(InputLabelStyle.Render("Project directory path:"))
	b.WriteString("\n")
	b.WriteString(InputStyle.Width(m.width - 6).Render(m.textInput.View()))
	b.WriteString("\n\n")
	b.WriteString(HelpStyle.Render("Enter the path to a directory containing package.json"))
	return lipgloss.Place(m.width, m.height-2, lipgloss.Left, lipgloss.Top,
		lipgloss.NewStyle().Padding(1, 2).Render(b.String()))
}

func (m Model) viewAuditNodeModules() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Audit node_modules"))
	b.WriteString("\n\n")
	b.WriteString(InputLabelStyle.Render("Path to node_modules directory:"))
	b.WriteString("\n")
	b.WriteString(InputStyle.Width(m.width - 6).Render(m.textInput.View()))
	b.WriteString("\n\n")
	b.WriteString(HelpStyle.Render("Enter the path to the node_modules directory to scan"))
	return lipgloss.Place(m.width, m.height-2, lipgloss.Left, lipgloss.Top,
		lipgloss.NewStyle().Padding(1, 2).Render(b.String()))
}

func (m Model) viewAuditTop() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Audit Top Repos"))
	b.WriteString("\n\n")
	b.WriteString(InputLabelStyle.Render("GitHub Category / Topic:"))
	b.WriteString("\n")
	b.WriteString(InputStyle.Width(m.width - 6).Render(m.textInput.View()))
	b.WriteString("\n\n")
	b.WriteString(HelpStyle.Render("Examples: web-framework, testing, utility, cli, backend"))
	b.WriteString("\n")
	b.WriteString(SubtitleStyle.Render("This will fetch the top 10 repos from GitHub and audit their npm versions."))
	return lipgloss.Place(m.width, m.height-2, lipgloss.Left, lipgloss.Top,
		lipgloss.NewStyle().Padding(1, 2).Render(b.String()))
}

func (m Model) viewSettings() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Settings"))
	b.WriteString("\n\n")

	labels := [FieldCount]string{"Registry URL", "Timeout (seconds)", "Min Severity", "Language"}
	for i := 0; i < int(FieldCount); i++ {
		style := InactiveFieldStyle
		if SettingsField(i) == m.settingsFocus {
			style = ActiveFieldStyle
		}
		b.WriteString(InputLabelStyle.Render(labels[i]))
		b.WriteString("\n")
		b.WriteString(style.Width(m.width - 8).Render(m.settingsFields[i].View()))
		b.WriteString("\n\n")
	}

	return lipgloss.Place(m.width, m.height-2, lipgloss.Left, lipgloss.Top,
		lipgloss.NewStyle().Padding(1, 2).Render(b.String()))
}

func (m Model) viewThreatIntel() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Threat Intelligence"))
	b.WriteString("\n\n")
	b.WriteString(InputLabelStyle.Render("Threat feed source URL:"))
	b.WriteString("\n")
	b.WriteString(InputStyle.Width(m.width - 6).Render(m.threatInput.View()))
	b.WriteString("\n\n")
	b.WriteString(HelpStyle.Render("Enter a threat intelligence feed URL to update local threat data"))
	return lipgloss.Place(m.width, m.height-2, lipgloss.Left, lipgloss.Top,
		lipgloss.NewStyle().Padding(1, 2).Render(b.String()))
}

func (m Model) viewResultsSummary() string {
	r := m.results
	var b strings.Builder

	// Package + duration
	if r.PackageName != "" {
		b.WriteString(DetailLabelStyle.Render("Package: "))
		b.WriteString(DetailValueStyle.Render(r.PackageName))
		b.WriteString("\n")
	}
	b.WriteString(DetailLabelStyle.Render("Duration: "))
	b.WriteString(DetailValueStyle.Render(r.Duration.String()))
	b.WriteString("\n")

	// Risk score bar
	b.WriteString(DetailLabelStyle.Render("Risk Score: "))
	scoreStr := fmt.Sprintf("%.0f/100", r.RiskScore)
	barWidth := 30
	bar := riskScoreBar(r.RiskScore, barWidth)
	b.WriteString(RiskBarStyle(r.RiskScore).Render(bar) + " " + DetailValueStyle.Render(scoreStr))
	b.WriteString("\n")

	// Severity breakdown
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, f := range r.Findings {
		counts[strings.ToLower(f.Severity)]++
	}
	b.WriteString(DetailLabelStyle.Render("Findings: "))
	b.WriteString(fmt.Sprintf("%d total", len(r.Findings)))
	b.WriteString("  ")
	b.WriteString(SevCriticalStyle.Render(fmt.Sprintf(" %d critical ", counts["critical"])))
	b.WriteString(" ")
	b.WriteString(SevHighStyle.Render(fmt.Sprintf("%d high", counts["high"])))
	b.WriteString(" ")
	b.WriteString(SevMediumStyle.Render(fmt.Sprintf("%d medium", counts["medium"])))
	b.WriteString(" ")
	b.WriteString(SevLowStyle.Render(fmt.Sprintf("%d low", counts["low"])))

	return b.String()
}

func (m Model) renderFindingDetail(idx int) string {
	if m.results == nil || idx >= len(m.results.Findings) {
		return ""
	}
	f := m.results.Findings[idx]

	var b strings.Builder
	b.WriteString(DetailLabelStyle.Render("Title:     "))
	b.WriteString(DetailValueStyle.Render(f.FindingTitle))
	b.WriteString("\n\n")

	b.WriteString(DetailLabelStyle.Render("Severity:  "))
	b.WriteString(SeverityStyle(strings.ToLower(f.Severity)).Render(f.Severity))
	b.WriteString("\n\n")

	b.WriteString(DetailLabelStyle.Render("Analyzer:  "))
	b.WriteString(DetailValueStyle.Render(f.Analyzer))
	b.WriteString("\n\n")

	if f.File != "" {
		b.WriteString(DetailLabelStyle.Render("Location:  "))
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			if f.Column > 0 {
				loc = fmt.Sprintf("%s:%d:%d", f.File, f.Line, f.Column)
			}
		}
		b.WriteString(DetailValueStyle.Render(loc))
		b.WriteString("\n\n")
	}

	b.WriteString(DetailLabelStyle.Render("Details:"))
	b.WriteString("\n")
	b.WriteString(DetailValueStyle.Render(f.Detail))
	b.WriteString("\n\n")

	if f.CodeExtract != "" {
		b.WriteString(DetailLabelStyle.Render("Code snippet:"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(f.CodeExtract))
		b.WriteString("\n\n")
	}

	if f.ExploitExample != "" {
		b.WriteString(DetailLabelStyle.Render("Attack Scenario:"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render(f.ExploitExample))
		b.WriteString("\n\n")
	}

	if f.Remediation != "" {
		b.WriteString(DetailLabelStyle.Render("Remediation:"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(f.Remediation))
	}

	return b.String()
}

func (m Model) viewRunning() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Running"))
	b.WriteString("\n\n")

	spinnerBox := BoxStyle.Width(m.width - 6).Render(
		fmt.Sprintf("%s %s", m.spinner.View(), m.runMsg))
	b.WriteString(spinnerBox)

	return lipgloss.Place(m.width, m.height-2, lipgloss.Center, lipgloss.Center,
		b.String())
}

func (m Model) viewSaveReport() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render("Save Report"))
	b.WriteString("\n\n")
	b.WriteString(InputLabelStyle.Render("Output file path:"))
	b.WriteString("\n")
	b.WriteString(InputStyle.Width(m.width - 6).Render(m.saveInput.View()))
	b.WriteString("\n\n")
	b.WriteString(HelpStyle.Render("Default: report.json. Supports .json and .txt extensions."))

	return lipgloss.Place(m.width, m.height-2, lipgloss.Left, lipgloss.Top,
		lipgloss.NewStyle().Padding(1, 2).Render(b.String()))
}
