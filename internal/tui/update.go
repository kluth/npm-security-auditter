package tui

import (
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.mainMenu.SetSize(30, msg.Height-6)
		m.findingsList.SetSize((msg.Width-34)/2, msg.Height-14)
		m.detailView.Width = (msg.Width - 34) / 2
		m.detailView.Height = msg.Height - 14
		return m, nil

	case tea.KeyMsg:
		// Global quit
		if msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}

	case auditCompleteMsg:
		m.results = msg.result
		m.screen = ScreenDashboard
		m.activePane = PaneFindings
		m.populateFindings()
		if len(m.results.Findings) > 0 {
			m.selectedIdx = 0
			m.detailView.SetContent(m.renderFindingDetail(0))
		}
		return m, nil

	case auditErrorMsg:
		m.err = msg.err
		m.screen = ScreenDashboard
		m.results = &AuditResult{Error: msg.err}
		return m, nil

	case reportSavedMsg:
		m.reportPath = msg.path
		m.screen = ScreenDashboard
		return m, nil

	case reportSaveErrorMsg:
		m.err = msg.err
		m.screen = ScreenDashboard
		return m, nil

	case threatUpdateMsg:
		m.screen = ScreenDashboard
		return m, nil

	case threatErrorMsg:
		m.err = msg.err
		m.screen = ScreenDashboard
		return m, nil
	}

	switch m.screen {
	case ScreenDashboard:
		return m.updateDashboard(msg)
	case ScreenAuditPackage:
		return m.updateAuditPackage(msg)
	case ScreenAuditProject:
		return m.updateAuditProject(msg)
	case ScreenAuditNodeModules:
		return m.updateAuditNodeModules(msg)
	case ScreenSettings:
		return m.updateSettings(msg)
	case ScreenThreatIntel:
		return m.updateThreatIntel(msg)
	case ScreenRunning:
		return m.updateRunning(msg)
	case ScreenSaveReport:
		return m.updateSaveReport(msg)
	default:
		return m.updateDashboard(msg)
	}
}

func (m Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			m.activePane = (m.activePane + 1) % 3
			return m, nil
		case "shift+tab":
			m.activePane = (m.activePane - 1 + 3) % 3
			return m, nil
		case "s":
			if m.results != nil {
				m.screen = ScreenSaveReport
				m.saveInput.SetValue("")
				m.saveInput.Focus()
				return m, m.saveInput.Cursor.BlinkCmd()
			}
		case "q":
			m.quitting = true
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	switch m.activePane {
	case PaneMenu:
		var mCmd tea.Cmd
		m, mCmd = m.updateMain(msg)
		return m, mCmd
	case PaneFindings:
		var fCmd tea.Cmd
		m, fCmd = m.updateResults(msg)
		return m, fCmd
	case PaneDetail:
		m.detailView, cmd = m.detailView.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) updateMain(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			idx := m.mainMenu.Index()
			switch idx {
			case 0:
				m.screen = ScreenAuditPackage
				m.textInput.SetValue("")
				m.textInput.Placeholder = "e.g. lodash@4.17.21"
				m.textInput.Focus()
				return m, m.textInput.Cursor.BlinkCmd()
			case 1:
				m.screen = ScreenAuditProject
				m.textInput.SetValue("")
				m.textInput.Placeholder = "e.g. /path/to/project"
				m.textInput.Focus()
				return m, m.textInput.Cursor.BlinkCmd()
			case 2:
				m.screen = ScreenAuditNodeModules
				m.textInput.SetValue("")
				m.textInput.Placeholder = "e.g. /path/to/node_modules"
				m.textInput.Focus()
				return m, m.textInput.Cursor.BlinkCmd()
			case 3:
				m.screen = ScreenSettings
				m.settingsFocus = FieldRegistry
				for i := range m.settingsFields {
					m.settingsFields[i].Blur()
				}
				m.settingsFields[0].Focus()
				return m, m.settingsFields[0].Cursor.BlinkCmd()
			case 4:
				m.screen = ScreenThreatIntel
				m.threatInput.SetValue("")
				m.threatInput.Focus()
				return m, m.threatInput.Cursor.BlinkCmd()
			case 5:
				if m.results != nil {
					m.activePane = PaneFindings
				}
				return m, nil
			}
		}
	}
	var cmd tea.Cmd
	m.mainMenu, cmd = m.mainMenu.Update(msg)
	return m, cmd
}

func (m Model) updateAuditPackage(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.screen = ScreenDashboard
			return m, nil
		case "enter":
			val := m.textInput.Value()
			if val == "" {
				return m, nil
			}
			m.runMsg = "Auditing package: " + val
			m.screen = ScreenRunning
			m.auditFn = func() tea.Msg {
				return runPackageAudit(val, m.settingsValues)
			}
			return m, tea.Batch(m.spinner.Tick, func() tea.Msg { return m.auditFn() })
		}
	}
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m Model) updateAuditProject(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.screen = ScreenDashboard
			return m, nil
		case "enter":
			val := m.textInput.Value()
			if val == "" {
				return m, nil
			}
			m.runMsg = "Auditing project: " + val
			m.screen = ScreenRunning
			m.auditFn = func() tea.Msg {
				return runProjectAudit(val, m.settingsValues)
			}
			return m, tea.Batch(m.spinner.Tick, func() tea.Msg { return m.auditFn() })
		}
	}
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m Model) updateAuditNodeModules(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.screen = ScreenDashboard
			return m, nil
		case "enter":
			val := m.textInput.Value()
			if val == "" {
				return m, nil
			}
			m.runMsg = "Auditing node_modules: " + val
			m.screen = ScreenRunning
			m.auditFn = func() tea.Msg {
				return runNodeModulesAudit(val, m.settingsValues)
			}
			return m, tea.Batch(m.spinner.Tick, func() tea.Msg { return m.auditFn() })
		}
	}
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m Model) updateSettings(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			// Save values back
			m.settingsValues.Registry = m.settingsFields[FieldRegistry].Value()
			m.settingsValues.Timeout = m.settingsFields[FieldTimeout].Value()
			m.settingsValues.Severity = m.settingsFields[FieldSeverity].Value()
			m.settingsValues.Language = m.settingsFields[FieldLanguage].Value()
			m.screen = ScreenDashboard
			return m, nil
		case "tab", "down":
			m.settingsFields[m.settingsFocus].Blur()
			m.settingsFocus = (m.settingsFocus + 1) % FieldCount
			m.settingsFields[m.settingsFocus].Focus()
			return m, m.settingsFields[m.settingsFocus].Cursor.BlinkCmd()
		case "shift+tab", "up":
			m.settingsFields[m.settingsFocus].Blur()
			m.settingsFocus = (m.settingsFocus - 1 + FieldCount) % FieldCount
			m.settingsFields[m.settingsFocus].Focus()
			return m, m.settingsFields[m.settingsFocus].Cursor.BlinkCmd()
		}
	}
	var cmd tea.Cmd
	m.settingsFields[m.settingsFocus], cmd = m.settingsFields[m.settingsFocus].Update(msg)
	return m, cmd
}

func (m Model) updateThreatIntel(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.screen = ScreenDashboard
			return m, nil
		case "enter":
			val := m.threatInput.Value()
			if val == "" {
				return m, nil
			}
			m.runMsg = "Updating threat intelligence..."
			m.screen = ScreenRunning
			m.auditFn = func() tea.Msg {
				return runThreatUpdate(val)
			}
			return m, tea.Batch(m.spinner.Tick, func() tea.Msg { return m.auditFn() })
		}
	}
	var cmd tea.Cmd
	m.threatInput, cmd = m.threatInput.Update(msg)
	return m, cmd
}

func (m Model) updateResults(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if m.results != nil && len(m.results.Findings) > 0 {
				m.selectedIdx = m.findingsList.Index()
				m.detailView.SetContent(m.renderFindingDetail(m.selectedIdx))
				m.detailView.GotoTop()
				return m, nil
			}
		}
	}
	var cmd tea.Cmd
	m.findingsList, cmd = m.findingsList.Update(msg)
	// Auto-update detail when findings list selection changes
	newIdx := m.findingsList.Index()
	if newIdx != m.selectedIdx && m.results != nil && len(m.results.Findings) > newIdx {
		m.selectedIdx = newIdx
		m.detailView.SetContent(m.renderFindingDetail(m.selectedIdx))
		m.detailView.GotoTop()
	}
	return m, cmd
}

func (m Model) updateRunning(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.spinner, cmd = m.spinner.Update(msg)
	return m, cmd
}

func (m Model) updateSaveReport(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.screen = ScreenDashboard
			return m, nil
		case "enter":
			path := m.saveInput.Value()
			if path == "" {
				path = "report.json"
			}
			return m, func() tea.Msg {
				return saveReport(m.results, path)
			}
		}
	}
	var cmd tea.Cmd
	m.saveInput, cmd = m.saveInput.Update(msg)
	return m, cmd
}

func (m *Model) populateFindings() {
	if m.results == nil {
		return
	}
	items := make([]list.Item, len(m.results.Findings))
	for i, f := range m.results.Findings {
		items[i] = f
	}
	m.findingsList.SetItems(items)
}
