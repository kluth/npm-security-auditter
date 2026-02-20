package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kluth/npm-security-auditter/internal/tui"
)

// runTUI launches the full-screen Bubble Tea application.
// It replaces the previous limited TUI implementation.
func runTUI() error {
	m := tui.NewModel()
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}
	return nil
}
