package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	ColorPrimary   = lipgloss.Color("#7C3AED")
	ColorSecondary = lipgloss.Color("#06B6D4")
	ColorDanger    = lipgloss.Color("#EF4444")
	ColorWarning   = lipgloss.Color("#F59E0B")
	ColorSuccess   = lipgloss.Color("#10B981")
	ColorMuted     = lipgloss.Color("#6B7280")
	ColorBg        = lipgloss.Color("#1E1E2E")
	ColorFg        = lipgloss.Color("#CDD6F4")
	ColorAccent    = lipgloss.Color("#F5C2E7")

	// Base styles
	AppStyle = lipgloss.NewStyle().
			Background(ColorBg)

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorAccent).
			Background(lipgloss.Color("#313244")).
			Padding(0, 2).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Italic(true)

	// Status bar
	StatusBarStyle = lipgloss.NewStyle().
			Foreground(ColorFg).
			Background(lipgloss.Color("#313244")).
			Padding(0, 1)

	StatusKeyStyle = lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true)

	// Input styles
	InputLabelStyle = lipgloss.NewStyle().
			Foreground(ColorSecondary).
			Bold(true).
			MarginRight(1)

	InputStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1).
			MarginTop(1)

	// Card / Box
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(1, 2).
			MarginTop(1)

	// Severity styles
	SevCriticalStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(ColorDanger).
				Bold(true).
				Padding(0, 1)

	SevHighStyle = lipgloss.NewStyle().
			Foreground(ColorDanger).
			Bold(true)

	SevMediumStyle = lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true)

	SevLowStyle = lipgloss.NewStyle().
			Foreground(ColorSecondary)

	// Risk score
	RiskBarHighStyle = lipgloss.NewStyle().
				Foreground(ColorDanger)

	RiskBarMedStyle = lipgloss.NewStyle().
			Foreground(ColorWarning)

	RiskBarLowStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess)

	// Spinner
	SpinnerStyle = lipgloss.NewStyle().
			Foreground(ColorPrimary)

	// Help / footer
	HelpStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			MarginTop(1)

	// Detail view
	DetailHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorAccent).
				MarginBottom(1)

	DetailLabelStyle = lipgloss.NewStyle().
				Foreground(ColorSecondary).
				Bold(true)

	DetailValueStyle = lipgloss.NewStyle().
				Foreground(ColorFg)

	// Tab-like active field indicator
	ActiveFieldStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorPrimary).
				Padding(0, 1)

	InactiveFieldStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorMuted).
				Padding(0, 1)

	// Success / Error messages
	SuccessStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorDanger).
			Bold(true)

	// Dashboard Pane styles
	PaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorMuted).
			Padding(0, 1)

	FocusedPaneStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorPrimary).
				Padding(0, 1)
)

func SeverityStyle(sev string) lipgloss.Style {
	switch sev {
	case "critical":
		return SevCriticalStyle
	case "high":
		return SevHighStyle
	case "medium":
		return SevMediumStyle
	default:
		return SevLowStyle
	}
}

func RiskBarStyle(score float64) lipgloss.Style {
	switch {
	case score >= 70:
		return RiskBarHighStyle
	case score >= 40:
		return RiskBarMedStyle
	default:
		return RiskBarLowStyle
	}
}
