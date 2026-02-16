package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TreeModel displays a dependency tree.
type TreeModel struct {
	Root  *DependencyNode
	Width int
}

// DependencyNode represents a package in the tree.
type DependencyNode struct {
	Name     string
	Version  string
	Severity string // "critical", "high", etc.
	Children []*DependencyNode
	Expanded bool
}

// NewTreeModel creates a new tree visualizer.
// In a real implementation, we would parse package-lock.json or yarn.lock to build this tree.
// For now, this is a placeholder/demo structure.
func NewTreeModel() TreeModel {
	root := &DependencyNode{
		Name:     "root-project",
		Version:  "1.0.0",
		Expanded: true,
		Children: []*DependencyNode{
			{Name: "express", Version: "4.17.1", Children: []*DependencyNode{
				{Name: "qs", Version: "6.7.0"},
				{Name: "debug", Version: "2.6.9", Severity: "low"},
			}},
			{Name: "lodash", Version: "4.17.15", Severity: "high", Expanded: true, Children: []*DependencyNode{
				{Name: "malicious-sub", Version: "0.0.1", Severity: "critical"},
			}},
		},
	}
	return TreeModel{Root: root}
}

func (m TreeModel) Init() tea.Cmd {
	return nil
}

func (m TreeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m TreeModel) View() string {
	var s strings.Builder
	s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render("Dependency Tree (Demo)"))
	s.WriteString("\n\n")
	m.renderNode(&s, m.Root, "")
	s.WriteString("\nPress 'q' to quit.\n")
	return s.String()
}

func (m TreeModel) renderNode(s *strings.Builder, node *DependencyNode, prefix string) {
	nameColor := lipgloss.Color("255")
	if node.Severity == "critical" {
		nameColor = lipgloss.Color("196")
	} else if node.Severity == "high" {
		nameColor = lipgloss.Color("208")
	}

	style := lipgloss.NewStyle().Foreground(nameColor)
	icon := "📦"
	if node.Severity != "" {
		icon = "⚠️"
	}

	s.WriteString(prefix + icon + " " + style.Render(fmt.Sprintf("%s@%s", node.Name, node.Version)))
	if node.Severity != "" {
		s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprintf(" [%s]", strings.ToUpper(node.Severity))))
	}
	s.WriteString("\n")

	if node.Expanded {
		for i, child := range node.Children {
			connector := "├── "
			if i == len(node.Children)-1 {
				connector = "└── "
			}
			m.renderNode(s, child, prefix+connector)
			// Reset prefix for subsequent siblings is handled by recursion logic,
			// but we need to pass the *correct* prefix for the child's children.
			// Actually simpler:
			// renderNode(child, prefix + (if last "    " else "│   "))
		}
	}
}
