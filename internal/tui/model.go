package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/kluth/npm-security-auditter/internal/analyzer"
)

// Screen represents which screen is currently active.
type Screen int

const (
	ScreenMain Screen = iota
	ScreenAuditPackage
	ScreenAuditProject
	ScreenAuditNodeModules
	ScreenSettings
	ScreenThreatIntel
	ScreenResults
	ScreenResultDetail
	ScreenRunning
	ScreenSaveReport
	ScreenAuditTop
	ScreenDashboard // New dashboard screen
)

// Pane identifies which part of the dashboard is focused.
type Pane int

const (
	PaneMenu Pane = iota
	PaneFindings
	PaneDetail
)

// MenuItem is an item in a list.
type MenuItem struct {
	title string
	desc  string
}

func (m MenuItem) Title() string       { return m.title }
func (m MenuItem) Description() string { return m.desc }
func (m MenuItem) FilterValue() string { return m.title }

// Finding holds a single audit finding for display.
type Finding struct {
	Analyzer       string
	Severity       string
	FindingTitle   string
	Detail         string
	File           string
	Line           int
	Column         int
	CodeExtract    string
	ExploitExample string
	Remediation    string
}

func (f Finding) FilterValue() string { return f.FindingTitle }
func (f Finding) Title() string {
	return fmt.Sprintf("[%s] %s", f.Severity, f.FindingTitle)
}
func (f Finding) Description() string {
	if f.File != "" {
		return fmt.Sprintf("%s — %s:%d", f.Analyzer, f.File, f.Line)
	}
	return f.Analyzer
}

// AuditResult holds the full result of an audit run.
type AuditResult struct {
	PackageName string
	RiskScore   float64
	Findings    []Finding
	RawFindings []analyzer.Finding
	Duration    time.Duration
	Error       error
}

// SettingsField identifies which setting is being edited.
type SettingsField int

const (
	FieldRegistry SettingsField = iota
	FieldTimeout
	FieldSeverity
	FieldLanguage
	FieldCount
)

// Model is the top-level Bubble Tea model.
type Model struct {
	screen       Screen
	activePane   Pane // Track focus in dashboard
	width        int
	height       int
	quitting     bool
	err          error

	// Main menu
	mainMenu list.Model

	// Text inputs (reused across screens)
	textInput textinput.Model

	// Settings
	settingsFields  [FieldCount]textinput.Model
	settingsFocus   SettingsField
	settingsValues  SettingsConfig

	// Threat intel
	threatInput textinput.Model

	// Running state
	spinner  spinner.Model
	runMsg   string
	auditFn  func() tea.Msg

	// Results
	results       *AuditResult
	findingsList  list.Model
	selectedIdx   int
	detailView    viewport.Model
	saveInput     textinput.Model

	// Report save path
	reportPath string
}

// SettingsConfig holds persisted settings values.
type SettingsConfig struct {
	Registry string
	Timeout  string
	Severity string
	Language string
}

// Messages
type auditCompleteMsg struct{ result *AuditResult }
type auditErrorMsg struct{ err error }
type reportSavedMsg struct{ path string }
type reportSaveErrorMsg struct{ err error }
type threatUpdateMsg struct{ msg string }
type threatErrorMsg struct{ err error }

func NewModel() Model {
	// Main menu
	items := []list.Item{
		MenuItem{title: "Audit Package", desc: "Scan a single npm package by name"},
		MenuItem{title: "Audit Project", desc: "Scan a project directory's package.json"},
		MenuItem{title: "Audit node_modules", desc: "Scan installed node_modules directory"},
		MenuItem{title: "Audit Top Repos", desc: "Audit top GitHub repos by category"},
		MenuItem{title: "Settings", desc: "Configure registry, timeout, severity, language"},
		MenuItem{title: "Threat Intelligence", desc: "Update threat intelligence sources"},
		MenuItem{title: "Results", desc: "View last audit results and findings"},
	}
	mainMenu := list.New(items, list.NewDefaultDelegate(), 0, 0)
	mainMenu.Title = "npm-security-auditter"
	mainMenu.SetShowStatusBar(false)
	mainMenu.SetFilteringEnabled(false)
	mainMenu.DisableQuitKeybindings()

	// Spinner
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = SpinnerStyle

	// Text input for package name
	ti := textinput.New()
	ti.Placeholder = "e.g. lodash@4.17.21"
	ti.CharLimit = 256
	ti.Width = 50

	// Settings fields
	var sf [FieldCount]textinput.Model
	placeholders := [FieldCount]string{
		"https://registry.npmjs.org",
		"30",
		"low",
		"en",
	}
	labels := [FieldCount]string{
		"Registry URL",
		"Timeout (seconds)",
		"Min Severity (low/medium/high/critical)",
		"Language",
	}
	defaults := SettingsConfig{
		Registry: "https://registry.npmjs.org",
		Timeout:  "30",
		Severity: "low",
		Language: "en",
	}
	vals := [FieldCount]string{defaults.Registry, defaults.Timeout, defaults.Severity, defaults.Language}
	for i := 0; i < int(FieldCount); i++ {
		sf[i] = textinput.New()
		sf[i].Placeholder = placeholders[i]
		sf[i].Prompt = labels[i] + ": "
		sf[i].CharLimit = 256
		sf[i].Width = 50
		sf[i].SetValue(vals[i])
	}
	sf[0].Focus()

	// Threat input
	threatIn := textinput.New()
	threatIn.Placeholder = "e.g. https://threat-feed.example.com/feed.json"
	threatIn.CharLimit = 512
	threatIn.Width = 60

	// Save input
	saveIn := textinput.New()
	saveIn.Placeholder = "report.json"
	saveIn.CharLimit = 256
	saveIn.Width = 50

	// Findings list (empty initially)
	fl := list.New(nil, list.NewDefaultDelegate(), 0, 0)
	fl.Title = "Findings"
	fl.SetShowStatusBar(true)
	fl.SetFilteringEnabled(true)
	fl.DisableQuitKeybindings()

	// Detail viewport
	dv := viewport.New(0, 0)

	return Model{
		screen:         ScreenDashboard,
		mainMenu:       mainMenu,
		textInput:      ti,
		settingsFields: sf,
		settingsFocus:  FieldRegistry,
		settingsValues: defaults,
		threatInput:    threatIn,
		spinner:        sp,
		findingsList:   fl,
		detailView:     dv,
		saveInput:      saveIn,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tea.EnterAltScreen)
}

// helpers

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func riskScoreBar(score float64, width int) string {
	filled := int(score / 100.0 * float64(width))
	filled = clamp(filled, 0, width)
	empty := width - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	return bar
}
