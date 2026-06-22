// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package tui

import (
	"net"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"jumpbox/internal/audit"
	"jumpbox/internal/i18n"
	"jumpbox/internal/keysvc"
)

// enterKeyForm, yeni SSH anahtarı adı girişi ekranını hazırlar.
func (m appModel) enterKeyForm() appModel {
	ti := textinput.New()
	ti.Placeholder = "prod-key"
	ti.CharLimit = 64
	ti.Width = 30
	ti.Focus()
	m.input = ti
	m.inputKind = inputKeyName
	m.state = stKeyForm
	return m
}

// enterGroupForm, yeni grup adı girişi ekranını hazırlar.
func (m appModel) enterGroupForm() appModel {
	ti := textinput.New()
	ti.Placeholder = "prod"
	ti.CharLimit = 64
	ti.Width = 30
	ti.Focus()
	m.input = ti
	m.inputKind = inputGroupName
	m.state = stGroupForm
	return m
}

// enterIPForm, seçili kullanıcıya izinli IP ekleme ekranını hazırlar.
func (m appModel) enterIPForm() appModel {
	ti := textinput.New()
	ti.Placeholder = "10.0.0.0/24"
	ti.CharLimit = 64
	ti.Width = 30
	ti.Focus()
	m.input = ti
	m.inputKind = inputIP
	m.state = stIPForm
	return m
}

func (m appModel) updateInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			switch m.inputKind {
			case inputIP:
				m.state = stUserIPs
			case inputGroupName:
				m.state = stGroups
			default:
				m.state = stKeys
			}
			return m, nil
		case "enter":
			return m.submitInput()
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m appModel) submitInput() (tea.Model, tea.Cmd) {
	lang := m.sess.Lang
	val := strings.TrimSpace(m.input.Value())

	switch m.inputKind {
	case inputKeyName:
		if val == "" {
			return m, nil
		}
		pub, err := keysvc.Generate(m.deps.Store, m.deps.Vault, val)
		if err != nil {
			return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stKeys), nil
		}
		m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionKeyAdd, val, m.sess.IP, "")
		m.loadSSHKeys()
		return m.showMessage(i18n.T(lang, "keys.created", pub), true, stKeys), nil

	case inputIP:
		if !validIPOrCIDR(val) {
			return m.showMessage(i18n.T(lang, "ips.invalid"), false, stUserIPs), nil
		}
		if err := m.deps.Store.AddAllowedIP(m.manageUser.ID, val); err != nil {
			return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stUserIPs), nil
		}
		m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionIPAdd, m.manageUser.Username, m.sess.IP, val)
		m.loadUserIPs()
		return m.showMessage(i18n.T(lang, "ips.added"), true, stUserIPs), nil

	case inputGroupName:
		if val == "" {
			return m, nil
		}
		if _, err := m.deps.Store.GetGroupByName(val); err == nil {
			return m.showMessage(i18n.T(lang, "groups.exists"), false, stGroups), nil
		}
		if _, err := m.deps.Store.CreateGroup(val); err != nil {
			return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stGroups), nil
		}
		m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionGroupAdd, val, m.sess.IP, "")
		m.loadGroups()
		return m.showMessage(i18n.T(lang, "groups.created"), true, stGroups), nil
	}
	return m, nil
}

func (m appModel) viewInput() string {
	lang := m.sess.Lang
	var title, prompt, hint string
	switch m.inputKind {
	case inputIP:
		title = i18n.T(lang, "ips.add_title")
		prompt = i18n.T(lang, "ips.add_prompt")
		hint = i18n.T(lang, "ips.form_hint")
	case inputGroupName:
		title = i18n.T(lang, "groups.new_title")
		prompt = i18n.T(lang, "groups.new_name")
		hint = i18n.T(lang, "keys.form_hint")
	default:
		title = i18n.T(lang, "keys.new_title")
		prompt = i18n.T(lang, "keys.new_name")
		hint = i18n.T(lang, "keys.form_hint")
	}
	body := prompt + m.input.View()
	return "\n" + titleStyle.Render(title) + "\n\n" + boxStyle.Render(body) + "\n" + dimStyle.Render(hint) + "\n"
}

// validIPOrCIDR, bir dizgenin geçerli bir IP veya CIDR olup olmadığını döndürür.
func validIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
