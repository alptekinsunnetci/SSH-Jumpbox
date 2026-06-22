// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"jumpbox/internal/audit"
	"jumpbox/internal/auth"
	"jumpbox/internal/i18n"
	"jumpbox/internal/model"
)

// ---- Kullanıcı listesi ----

func (m *appModel) loadUsers() {
	users, _ := m.deps.Store.ListUsers()
	m.users = users
	if m.userCur >= len(m.users) {
		m.userCur = 0
	}
}

func (m appModel) updateUsers(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	lang := m.sess.Lang
	switch lowerKey(msg) {
	case "esc", "q":
		m.state = stMenu
	case "up", "k":
		if m.userCur > 0 {
			m.userCur--
		}
	case "down", "j":
		if m.userCur < len(m.users)-1 {
			m.userCur++
		}
	case "n":
		m.uform = newUserForm(lang)
		m.state = stUserForm
	case "d":
		if len(m.users) > 0 {
			u := m.users[m.userCur]
			if u.ID == m.sess.UserID {
				return m.showMessage(i18n.T(lang, "users.self_delete"), false, stUsers), nil
			}
			return m.askConfirm(confirmUser, u.ID, u.Username, "", stUsers), nil
		}
	case "i":
		if len(m.users) > 0 {
			m.manageUser = m.users[m.userCur]
			m.loadUserIPs()
			m.ipCur = 0
			m.state = stUserIPs
		}
	case "g":
		if len(m.users) > 0 {
			m.manageUser = m.users[m.userCur]
			m.ugCur = 0
			m.loadUserGroups()
			m.state = stUserGroups
		}
	}
	return m, nil
}

func (m appModel) viewUsers() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "users.title"))
	if len(m.users) == 0 {
		return "\n" + title + "\n\n" + dimStyle.Render(i18n.T(lang, "users.empty")) +
			"\n\n" + dimStyle.Render(i18n.T(lang, "users.hint")) + "\n"
	}
	lines := ""
	for i, u := range m.users {
		cursor := "  "
		admin := i18n.T(lang, "users.admin_no")
		if u.IsAdmin {
			admin = i18n.T(lang, "users.admin_yes")
		}
		label := fmt.Sprintf("%-20s [%s: %s]", u.Username, i18n.T(lang, "users.col_admin"), admin)
		if i == m.userCur {
			cursor = "▸ "
			label = selectedStyle.Render(label)
		}
		lines += cursor + label + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "users.hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(lines) + "\n" + hint + "\n"
}

// ---- Yeni kullanıcı formu ----

type userForm struct {
	inputs  []textinput.Model // 0: kullanıcı adı, 1: parola
	focus   int               // 0,1 = metin alanları; 2 = admin toggle
	isAdmin bool
}

func newUserForm(lang string) userForm {
	f := userForm{inputs: make([]textinput.Model, 2)}
	for i := range f.inputs {
		ti := textinput.New()
		ti.CharLimit = 64
		ti.Width = 30
		f.inputs[i] = ti
	}
	f.inputs[1].EchoMode = textinput.EchoPassword
	f.inputs[1].EchoCharacter = '•'
	f.focus = 0
	f.inputs[0].Focus()
	return f
}

func (f *userForm) refocus() {
	for i := range f.inputs {
		if i == f.focus {
			f.inputs[i].Focus()
		} else {
			f.inputs[i].Blur()
		}
	}
}

func (m appModel) updateUserForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.state = stUsers
			return m, nil
		case "tab", "down":
			m.uform.focus = (m.uform.focus + 1) % 3
			m.uform.refocus()
			return m, nil
		case "shift+tab", "up":
			m.uform.focus = (m.uform.focus + 2) % 3
			m.uform.refocus()
			return m, nil
		case "enter":
			return m.saveUser()
		case " ", "left", "right":
			if m.uform.focus == 2 {
				m.uform.isAdmin = !m.uform.isAdmin
				return m, nil
			}
		}
	}
	if m.uform.focus < 2 {
		var cmd tea.Cmd
		m.uform.inputs[m.uform.focus], cmd = m.uform.inputs[m.uform.focus].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m appModel) saveUser() (tea.Model, tea.Cmd) {
	lang := m.sess.Lang
	username := strings.TrimSpace(m.uform.inputs[0].Value())
	password := m.uform.inputs[1].Value()

	if username == "" {
		return m.showMessage(i18n.T(lang, "servers.invalid", i18n.T(lang, "users.field_username")), false, stUserForm), nil
	}
	if len(password) < 8 {
		return m.showMessage(i18n.T(lang, "users.password_short"), false, stUserForm), nil
	}
	if _, err := m.deps.Store.GetUserByUsername(username); err == nil {
		return m.showMessage(i18n.T(lang, "users.exists"), false, stUserForm), nil
	}

	hash, err := auth.HashPassword(password, m.deps.BcryptCost)
	if err != nil {
		return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stUsers), nil
	}
	key, err := auth.GenerateTOTPSecret(m.deps.Issuer, username)
	if err != nil {
		return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stUsers), nil
	}
	if _, err := m.deps.Store.CreateUser(model.User{
		Username:     username,
		PasswordHash: hash,
		TOTPSecret:   key.Secret(),
		Language:     m.sess.Lang,
		IsAdmin:      m.uform.isAdmin,
	}); err != nil {
		return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stUsers), nil
	}
	m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionUserAdd, username, m.sess.IP, "")
	m.loadUsers()

	account := fmt.Sprintf("%s (%s)", m.deps.Issuer, username)
	return m.showMessage(i18n.T(lang, "users.created", account, key.Secret()), true, stUsers), nil
}

func (m appModel) viewUserForm() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "users.new_title"))
	labels := []string{
		i18n.T(lang, "users.field_username"),
		i18n.T(lang, "users.field_password"),
	}
	body := ""
	for i, ti := range m.uform.inputs {
		marker := "  "
		label := labels[i]
		if i == m.uform.focus {
			marker = "▸ "
			label = selectedStyle.Render(label)
		}
		body += fmt.Sprintf("%s%-22s %s\n", marker, label, ti.View())
	}
	// Admin toggle satırı (focus == 2).
	adminVal := i18n.T(lang, "users.admin_no")
	if m.uform.isAdmin {
		adminVal = i18n.T(lang, "users.admin_yes")
	}
	marker := "  "
	adminLabel := i18n.T(lang, "users.field_admin")
	if m.uform.focus == 2 {
		marker = "▸ "
		adminLabel = selectedStyle.Render(adminLabel)
	}
	body += fmt.Sprintf("%s%-22s [%s]\n", marker, adminLabel, adminVal)

	hint := dimStyle.Render(i18n.T(lang, "users.form_hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(body) + "\n" + hint + "\n"
}

// ---- Seçili kullanıcının izinli IP'leri ----

func (m *appModel) loadUserIPs() {
	ips, _ := m.deps.Store.ListAllowedIPs(m.manageUser.ID)
	m.userIPs = ips
	if m.ipCur >= len(m.userIPs) {
		m.ipCur = 0
	}
}

func (m appModel) updateUserIPs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch lowerKey(msg) {
	case "esc", "q":
		m.state = stUsers
	case "up", "k":
		if m.ipCur > 0 {
			m.ipCur--
		}
	case "down", "j":
		if m.ipCur < len(m.userIPs)-1 {
			m.ipCur++
		}
	case "a":
		return m.enterIPForm(), nil
	case "d":
		if len(m.userIPs) > 0 {
			ip := m.userIPs[m.ipCur]
			return m.askConfirm(confirmIP, 0, ip, ip, stUserIPs), nil
		}
	}
	return m, nil
}

func (m appModel) viewUserIPs() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "ips.title", m.manageUser.Username))
	if len(m.userIPs) == 0 {
		return "\n" + title + "\n\n" + dimStyle.Render(i18n.T(lang, "ips.empty")) +
			"\n\n" + dimStyle.Render(i18n.T(lang, "ips.hint")) + "\n"
	}
	lines := ""
	for i, ip := range m.userIPs {
		cursor := "  "
		label := ip
		if i == m.ipCur {
			cursor = "▸ "
			label = selectedStyle.Render(label)
		}
		lines += cursor + label + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "ips.hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(lines) + "\n" + hint + "\n"
}
