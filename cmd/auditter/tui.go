package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

var (
	logoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Bold(true).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("81")).
			Bold(true).
			MarginBottom(1)

	focusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

const logo = `
    ___             _ _ _   _            
   / _ \           | (_) | | |           
  / /_\ \_   _  __| |_| |_| |_ ___ _ __  
  |  _  | | | |/ _` + "`" + ` | | __| __/ _ \ '__| 
  | | | | |_| | (_| | | |_| ||  __/ |    
  \_| |_/\__,_|\__,_|_|\__|\__\___|_|    
`

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
	ti.Width = 30
	ti.PromptStyle = focusedStyle
	ti.TextStyle = focusedStyle

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
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.state == stateConfig {
				m.state = stateInput
				return m, nil
			}
			return m, tea.Quit
		case "backspace":
			if m.state == stateConfig {
				m.state = stateInput
				return m, nil
			}
		case "enter":
			if m.state == stateInput {
				m.pkgName = m.pkgInput.Value()
				if m.pkgName != "" {
					m.state = stateConfig
				}
				return m, nil
			}
			if m.state == stateConfig {
				if m.cursor == 2 {
					m.state = stateRunning
					return m, m.runAudit
				}
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
		return m, nil // Don't quit immediately so user can see result
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

	s.WriteString(logoStyle.Render(logo))
	s.WriteString("\n")

	switch m.state {
	case stateInput:
		s.WriteString(headerStyle.Render("Package Audit Selection"))
		s.WriteString("\n\nEnter package name to audit:\n\n")
		s.WriteString(m.pkgInput.View())
		s.WriteString("\n\n" + dimStyle.Render("(esc to quit, enter to continue)"))

	case stateConfig:
		s.WriteString(headerStyle.Render(fmt.Sprintf("Audit Configuration: %s", m.pkgName)))
		s.WriteString("\n\n")

		// Format selection
		s.WriteString("Output Format: ")
		if m.cursor == 0 {
			s.WriteString(focusedStyle.Render("> " + m.formats[m.selectedFormat]))
		} else {
			s.WriteString("  " + m.formats[m.selectedFormat])
		}
		s.WriteString(dimStyle.Render(fmt.Sprintf(" [%d/%d]", m.selectedFormat+1, len(m.formats))))
		s.WriteString("\n")

		// Language selection
		s.WriteString("Language:      ")
		if m.cursor == 1 {
			s.WriteString(focusedStyle.Render("> " + m.langs[m.selectedLang]))
		} else {
			s.WriteString("  " + m.langs[m.selectedLang])
		}
		s.WriteString(dimStyle.Render(fmt.Sprintf(" [%d/%d]", m.selectedLang+1, len(m.langs))))
		s.WriteString("\n\n")

		if m.cursor == 2 {
			s.WriteString(focusedStyle.Render("> [ Start Audit ]"))
		} else {
			s.WriteString("  [ Start Audit ]")
		}
		s.WriteString("\n\n" + dimStyle.Render("(arrows to navigate, esc to go back, enter to start)"))

	case stateRunning:
		s.WriteString(headerStyle.Render(fmt.Sprintf("Auditing %s", m.pkgName)))
		s.WriteString(fmt.Sprintf("\n\n %s Analyzing package metrics and security patterns...\n\n", m.spinner.View()))

	case stateDone:
		s.WriteString(headerStyle.Render("Audit Complete"))
		s.WriteString(fmt.Sprintf("\n\n%s\n\n", m.resultMsg))
		if m.reportContent != "" {
			s.WriteString(m.reportContent)
			s.WriteString("\n\n")
		}
		s.WriteString(dimStyle.Render("(press any key to exit)"))
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
		analyzer.NewIssuesAnalyzer(),
		analyzer.NewShellScriptAnalyzer(),
		analyzer.NewScorecardAnalyzer(),
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
	for _, m := range pkg.Maintainers {
		info.Maintainers = append(info.Maintainers, m.Name)
	}
	if pkg.Repository != nil && pkg.Repository.URL != "" {
		info.RepoURL = pkg.Repository.URL
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

	// Sanitize filename for scoped packages
	safePkgName := strings.ReplaceAll(m.pkgName, "/", "-")
	safePkgName = strings.ReplaceAll(safePkgName, "@", "")
	filename := fmt.Sprintf("audit-%s.%s", safePkgName, format)
	
	var out io.Writer
	var buf bytes.Buffer
	var isTerminal bool

	if format == "terminal" {
		isTerminal = true
		out = &buf
	} else {
		f, err := os.Create(filename)
		if err != nil {
			return auditResultMsg{summary: fmt.Sprintf("Error creating file: %v", err)}
		}
		defer f.Close()
		out = f
	}

	rep := reporter.New(out, format, lang)
	if err := rep.Render(report); err != nil {
		return auditResultMsg{summary: fmt.Sprintf("Error rendering: %v", err)}
	}

	const colorReset = "\033[0m"
	scoreColor, scoreLabel := rep.GetRiskLevel(report.Score)
	summary := fmt.Sprintf("Audit Score: %s%d/100 (%s)%s\n", scoreColor, report.Score, scoreLabel, colorReset)
	
	if isTerminal {
		return auditResultMsg{
			summary: summary + "Report generated below:",
			content: buf.String(),
		}
	}

	return auditResultMsg{
		summary: summary + fmt.Sprintf("Report saved to %s", filename),
	}
}
