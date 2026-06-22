// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"jumpbox/internal/i18n"
)

const logsPageSize = 15

func (m appModel) updateLogs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "enter":
		m.state = stMenu
	case "up", "k":
		if m.logsTop > 0 {
			m.logsTop--
		}
	case "down", "j":
		if m.logsTop < m.maxLogsTop() {
			m.logsTop++
		}
	case "pgdown", "right", "l":
		m.logsTop += logsPageSize
		if m.logsTop > m.maxLogsTop() {
			m.logsTop = m.maxLogsTop()
		}
	case "pgup", "left", "h":
		m.logsTop -= logsPageSize
		if m.logsTop < 0 {
			m.logsTop = 0
		}
	}
	return m, nil
}

func (m appModel) maxLogsTop() int {
	if len(m.logs) <= logsPageSize {
		return 0
	}
	return len(m.logs) - logsPageSize
}

func (m appModel) viewLogs() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "logs.title"))
	if len(m.logs) == 0 {
		return "\n" + title + "\n\n" + dimStyle.Render(i18n.T(lang, "logs.empty")) +
			"\n\n" + dimStyle.Render(i18n.T(lang, "common.press_enter")) + "\n"
	}
	header := fmt.Sprintf("%-20s %-16s %-16s %-15s",
		i18n.T(lang, "logs.col_time"),
		i18n.T(lang, "logs.col_action"),
		i18n.T(lang, "logs.col_server"),
		i18n.T(lang, "logs.col_ip"))
	rows := headerStyle.Render(header) + "\n"

	end := m.logsTop + logsPageSize
	if end > len(m.logs) {
		end = len(m.logs)
	}
	for _, e := range m.logs[m.logsTop:end] {
		rows += fmt.Sprintf("%-20s %-16s %-16s %-15s\n",
			e.Timestamp.Local().Format("2006-01-02 15:04:05"),
			truncate(e.Action, 16),
			truncate(e.TargetServer, 16),
			truncate(e.IPAddress, 15))
	}
	hint := dimStyle.Render(fmt.Sprintf("%d-%d / %d  •  ↑/↓ • Enter", m.logsTop+1, end, len(m.logs)))
	return "\n" + title + "\n\n" + boxStyle.Render(rows) + "\n" + hint + "\n"
}
