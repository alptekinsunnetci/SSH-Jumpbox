// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"jumpbox/internal/i18n"
)

func (m *appModel) loadSSHKeys() {
	keys, _ := m.deps.Store.ListSSHKeys()
	m.sshKeys = keys
	if m.keyCur >= len(m.sshKeys) {
		m.keyCur = 0
	}
}

func (m appModel) updateKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch lowerKey(msg) {
	case "esc", "q":
		m.state = stMenu
	case "up", "k":
		if m.keyCur > 0 {
			m.keyCur--
		}
	case "down", "j":
		if m.keyCur < len(m.sshKeys)-1 {
			m.keyCur++
		}
	case "n":
		return m.enterKeyForm(), nil
	case "v":
		if len(m.sshKeys) > 0 {
			k := m.sshKeys[m.keyCur]
			return m.showMessage(k.Name+":\n\n"+k.PublicKey, true, stKeys), nil
		}
	case "d":
		if len(m.sshKeys) > 0 {
			k := m.sshKeys[m.keyCur]
			return m.askConfirm(confirmKey, k.ID, k.Name, "", stKeys), nil
		}
	}
	return m, nil
}

func (m appModel) viewKeys() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "keys.title"))
	if len(m.sshKeys) == 0 {
		return "\n" + title + "\n\n" + dimStyle.Render(i18n.T(lang, "keys.empty")) +
			"\n\n" + dimStyle.Render(i18n.T(lang, "keys.hint")) + "\n"
	}
	lines := ""
	for i, k := range m.sshKeys {
		cursor := "  "
		label := k.Name
		if i == m.keyCur {
			cursor = "▸ "
			label = selectedStyle.Render(label)
		}
		lines += cursor + label + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "keys.hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(lines) + "\n" + hint + "\n"
}
