// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"jumpbox/internal/audit"
	"jumpbox/internal/i18n"
)

// ---- Grup listesi (oluştur/sil) ----

func (m *appModel) loadGroups() {
	groups, _ := m.deps.Store.ListGroups()
	m.groups = groups
	if m.groupCur >= len(m.groups) {
		m.groupCur = 0
	}
}

func (m appModel) updateGroups(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch lowerKey(msg) {
	case "esc", "q":
		m.state = stMenu
	case "up", "k":
		if m.groupCur > 0 {
			m.groupCur--
		}
	case "down", "j":
		if m.groupCur < len(m.groups)-1 {
			m.groupCur++
		}
	case "n":
		return m.enterGroupForm(), nil
	case "d":
		if len(m.groups) > 0 {
			g := m.groups[m.groupCur]
			return m.askConfirm(confirmGroup, g.ID, g.Name, "", stGroups), nil
		}
	}
	return m, nil
}

func (m appModel) viewGroups() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "groups.title"))
	if len(m.groups) == 0 {
		return "\n" + title + "\n\n" + dimStyle.Render(i18n.T(lang, "groups.empty")) +
			"\n\n" + dimStyle.Render(i18n.T(lang, "groups.hint")) + "\n"
	}
	lines := ""
	for i, g := range m.groups {
		cursor := "  "
		label := g.Name
		if i == m.groupCur {
			cursor = "▸ "
			label = selectedStyle.Render(label)
		}
		lines += cursor + label + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "groups.hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(lines) + "\n" + hint + "\n"
}

// ---- Kullanıcı-grup erişim atama ----

func (m *appModel) loadUserGroups() {
	m.ugGroups, _ = m.deps.Store.ListGroups()
	m.ugSet, _ = m.deps.Store.ListUserGroupIDs(m.manageUser.ID)
	if m.ugSet == nil {
		m.ugSet = map[int64]bool{}
	}
	if m.ugCur >= len(m.ugGroups) {
		m.ugCur = 0
	}
}

func (m appModel) updateUserGroups(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch lowerKey(msg) {
	case "esc", "q":
		m.state = stUsers
	case "up", "k":
		if m.ugCur > 0 {
			m.ugCur--
		}
	case "down", "j":
		if m.ugCur < len(m.ugGroups)-1 {
			m.ugCur++
		}
	case " ", "enter":
		if len(m.ugGroups) == 0 {
			return m, nil
		}
		g := m.ugGroups[m.ugCur]
		if m.ugSet[g.ID] {
			_ = m.deps.Store.RemoveUserGroup(m.manageUser.ID, g.ID)
			m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionGroupRevk, m.manageUser.Username, m.sess.IP, g.Name)
		} else {
			_ = m.deps.Store.AddUserGroup(m.manageUser.ID, g.ID)
			m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionGroupGrant, m.manageUser.Username, m.sess.IP, g.Name)
		}
		m.loadUserGroups()
	}
	return m, nil
}

func (m appModel) viewUserGroups() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "usergroups.title", m.manageUser.Username))
	if len(m.ugGroups) == 0 {
		return "\n" + title + "\n\n" + dimStyle.Render(i18n.T(lang, "groups.empty")) +
			"\n\n" + dimStyle.Render(i18n.T(lang, "common.press_enter")) + "\n"
	}
	lines := ""
	for i, g := range m.ugGroups {
		cursor := "  "
		mark := "[ ]"
		if m.ugSet[g.ID] {
			mark = "[x]"
		}
		label := mark + " " + g.Name
		if i == m.ugCur {
			cursor = "▸ "
			label = selectedStyle.Render(label)
		}
		lines += cursor + label + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "usergroups.hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(lines) + "\n" + hint + "\n"
}
