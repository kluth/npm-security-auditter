package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kluth/npm-security-auditter/internal/analyzer"
	"github.com/kluth/npm-security-auditter/internal/registry"
	"github.com/kluth/npm-security-auditter/internal/reporter"
)

type model struct {
	state          sessionState
	pkgInput       textinput.Model
	formats        []string
	langs          []string
	cursor         int
	selectedFormat int
	selectedLang   int
	pkgName        string
	spinner        spinner.Model
	resultMsg      string
	err            error
	reportContent  string // Store report for display/save
}

type sessionState int

const (
	stateInput sessionState = iota
	stateConfig
	stateRunning
	stateDone
)

func initialModel() model {
	ti := textinput.New()
	ti.Placeholder = "lodash"
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 20

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return model{
		state:    stateInput,
		pkgInput: ti,
		formats:  []string{"terminal", "markdown", "html", "json", "csv", "pdf"},
		langs:    []string{"en", "de", "fr", "es", "it", "pt", "jp", "zh", "ru", "tlh", "vul", "sin"},
		spinner:  s,
	}
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "enter":
			if m.state == stateInput {
				m.pkgName = m.pkgInput.Value()
				if m.pkgName != "" {
					m.state = stateConfig
				}
				return m, nil
			}
			if m.state == stateConfig {
				m.state = stateRunning
				return m, m.runAudit
			}
			if m.state == stateDone {
				return m, tea.Quit
			}
		case "up", "k":
			if m.state == stateConfig {
				if m.cursor > 0 {
					m.cursor--
				}
			}
		case "down", "j":
			if m.state == stateConfig {
				if m.cursor < 2 { // format, lang, start
					m.cursor++
				}
			}
		case "left", "h":
			if m.state == stateConfig {
				if m.cursor == 0 && m.selectedFormat > 0 {
					m.selectedFormat--
				} else if m.cursor == 1 && m.selectedLang > 0 {
					m.selectedLang--
				}
			}
		case "right", "l":
			if m.state == stateConfig {
				if m.cursor == 0 && m.selectedFormat < len(m.formats)-1 {
					m.selectedFormat++
				} else if m.cursor == 1 && m.selectedLang < len(m.langs)-1 {
					m.selectedLang++
				}
			}
		}

	case auditResultMsg:
		m.state = stateDone
		m.resultMsg = msg.summary
		m.reportContent = msg.content
		return m, tea.Quit // For now, just quit after audit, or we could show result
	}

	if m.state == stateInput {
		m.pkgInput, cmd = m.pkgInput.Update(msg)
		return m, cmd
	}

	if m.state == stateRunning {
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m model) View() string {
	var s strings.Builder

	switch m.state {
	case stateInput:
		s.WriteString("Enter package name to audit:\n\n")
		s.WriteString(m.pkgInput.View())
		s.WriteString("\n\n(esc to quit)")

	case stateConfig:
		s.WriteString(fmt.Sprintf("Configuration for %s:\n\n", m.pkgName))

		// Format selection
		s.WriteString("Output Format: ")
		if m.cursor == 0 {
			s.WriteString("> ")
		} else {
			s.WriteString("  ")
		}
		s.WriteString(m.formats[m.selectedFormat])
		s.WriteString(fmt.Sprintf(" [%d/%d]", m.selectedFormat+1, len(m.formats)))
		s.WriteString("\n")

		// Language selection
		s.WriteString("Language:      ")
		if m.cursor == 1 {
			s.WriteString("> ")
		} else {
			s.WriteString("  ")
		}
		s.WriteString(m.langs[m.selectedLang])
		s.WriteString(fmt.Sprintf(" [%d/%d]", m.selectedLang+1, len(m.langs)))
		s.WriteString("\n\n")

		if m.cursor == 2 {
			s.WriteString("> [ Start Audit ]")
		} else {
			s.WriteString("  [ Start Audit ]")
		}
		s.WriteString("\n\n(use arrows to navigate, enter to select)")

	case stateRunning:
		s.WriteString(fmt.Sprintf("\n %s Auditing %s...\n\n", m.spinner.View(), m.pkgName))

	case stateDone:
		s.WriteString(fmt.Sprintf("\nAudit Complete!\n\n%s\n", m.resultMsg))
	}

	return s.String()
}

type auditResultMsg struct {
	summary string
	content string
}

func (m model) runAudit() tea.Msg {
	// This runs in a separate goroutine
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	client := registry.NewClient(registryURL)
	pkg, err := client.GetPackage(ctx, m.pkgName)
	if err != nil {
		return auditResultMsg{summary: fmt.Sprintf("Error: %v", err)}
	}

	latestTag, ok := pkg.DistTags["latest"]
	if !ok {
		return auditResultMsg{summary: "Error: no latest tag"}
	}
	version, ok := pkg.Versions[latestTag]
	if !ok {
		return auditResultMsg{summary: "Error: version not found"}
	}

	analyzers := []analyzer.Analyzer{
		analyzer.NewVulnAnalyzer(),
		analyzer.NewScriptsAnalyzer(),
		analyzer.NewTyposquatAnalyzer(),
		analyzer.NewMaintainerAnalyzer(),
		analyzer.NewMetadataAnalyzer(),
		analyzer.NewDepsAnalyzer(),
		analyzer.NewBinaryAnalyzer(),
		analyzer.NewProvenanceAnalyzer(),
		analyzer.NewTarballAnalyzer(),
		analyzer.NewRepoVerifierAnalyzer(),
	}
	if !noSandbox {
		analyzers = append(analyzers, analyzer.NewSandboxAnalyzer())
	}

	results := analyzer.RunAll(ctx, analyzers, pkg, &version)
	info := reporter.PackageInfo{
		License:       version.License,
		TotalVersions: len(pkg.Versions),
		Dependencies:  len(version.Dependencies),
		HasScripts:    hasInstallScripts(&version),
	}
	if created, ok := pkg.Time["created"]; ok {
		info.CreatedAt = created.Format("2006-01-02")
	}

	report := reporter.Report{
		Package: m.pkgName,
		Version: latestTag,
		Results: results,
		Info:    info,
	}

	format := m.formats[m.selectedFormat]
	lang := reporter.Language(m.langs[m.selectedLang])

	// Render to file or stdout simulation
	// For TUI, we might want to write to a file directly if it's PDF/HTML
	filename := fmt.Sprintf("audit-%s.%s", m.pkgName, format)
	if format == "terminal" {
		filename = "stdout" // special case
	}
	
	f, err := os.Create(filename)
	if err != nil {
		return auditResultMsg{summary: fmt.Sprintf("Error creating file: %v", err)}
	}
	defer f.Close()

	rep := reporter.New(f, format, lang)
	if err := rep.Render(report); err != nil {
		return auditResultMsg{summary: fmt.Sprintf("Error rendering: %v", err)}
	}

	msg := fmt.Sprintf("Report saved to %s", filename)
	if format == "terminal" {
		msg = "Audit finished. Check output." // Terminal output capture is tricky here
	}

	return auditResultMsg{summary: msg}
}
