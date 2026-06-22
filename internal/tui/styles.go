// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Padding(0, 1)
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	okStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("78"))
	headerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("250"))
	boxStyle      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).Padding(0, 1)
)
