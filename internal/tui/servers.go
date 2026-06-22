// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"jumpbox/internal/audit"
	"jumpbox/internal/i18n"
	"jumpbox/internal/model"
)

// loadServers, sunucu listesini tazeler. Admin tüm sunucuları görür; admin
// olmayan yalnızca izinli gruplarındaki sunucuları görür.
func (m *appModel) loadServers() {
	var servers []model.ServerView
	if m.sess.IsAdmin {
		servers, _ = m.deps.Store.ListServers()
	} else {
		servers, _ = m.deps.Store.ListServersForUser(m.sess.UserID)
	}
	m.servers = servers
	if m.pickCur >= len(m.servers) {
		m.pickCur = 0
	}
}

func (m *appModel) loadLogs() {
	logs, _ := m.deps.Store.ListAuditByUser(m.sess.UserID, 200)
	m.logs = logs
}

// ---- Sunucu listesi (salt görüntüleme) ----

func (m appModel) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "enter":
		m.state = stMenu
	}
	return m, nil
}

func (m appModel) viewList() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "servers.title"))
	if len(m.servers) == 0 {
		return "\n" + title + "\n\n" + dimStyle.Render(i18n.T(lang, "servers.empty")) +
			"\n\n" + dimStyle.Render(i18n.T(lang, "common.press_enter")) + "\n"
	}
	header := fmt.Sprintf("%-16s %-22s %-12s %-10s %-14s",
		i18n.T(lang, "servers.col_name"),
		i18n.T(lang, "servers.col_host"),
		i18n.T(lang, "servers.col_user"),
		i18n.T(lang, "servers.col_key"),
		i18n.T(lang, "servers.col_group"))
	rows := headerStyle.Render(header) + "\n"
	for _, s := range m.servers {
		key := s.KeyName
		if key == "" {
			key = i18n.T(lang, "servers.no_key")
		}
		group := s.GroupNames
		if group == "" {
			group = i18n.T(lang, "servers.no_key")
		}
		addr := fmt.Sprintf("%s:%d", s.IP, s.Port)
		rows += fmt.Sprintf("%-16s %-22s %-12s %-10s %-14s\n",
			truncate(s.Name, 16), truncate(addr, 22), truncate(s.Username, 12),
			truncate(key, 10), truncate(group, 14))
	}
	hint := dimStyle.Render(i18n.T(lang, "common.press_enter"))
	return "\n" + title + "\n\n" + boxStyle.Render(rows) + "\n" + hint + "\n"
}

// ---- Sunucu seçimi (bağlan/düzenle/sil) ----

func (m appModel) updatePick(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.state = stMenu
		return m, nil
	case "up", "k":
		if m.pickCur > 0 {
			m.pickCur--
		}
	case "down", "j":
		if m.pickCur < len(m.servers)-1 {
			m.pickCur++
		}
	case "enter", " ":
		if len(m.servers) == 0 {
			m.state = stMenu
			return m, nil
		}
		sel := m.servers[m.pickCur]
		switch m.purpose {
		case pickConnect:
			m.chosen = sel.Server
			m.action = ActionConnect
			return m, tea.Quit
		case pickEdit:
			m.form = newServerForm(m.sess.Lang, &sel, m.loadKeys(), m.loadGroupList())
			m.state = stForm
		case pickDelete:
			return m.askConfirm(confirmServer, sel.ID, sel.Name, "", stMenu), nil
		}
	}
	return m, nil
}

func (m appModel) viewPick() string {
	lang := m.sess.Lang
	var titleKey string
	switch m.purpose {
	case pickEdit:
		titleKey = "servers.select_edit"
	case pickDelete:
		titleKey = "servers.select_delete"
	default:
		titleKey = "servers.select_connect"
	}
	title := titleStyle.Render(i18n.T(lang, titleKey))
	if len(m.servers) == 0 {
		return "\n" + title + "\n\n" + dimStyle.Render(i18n.T(lang, "servers.empty")) +
			"\n\n" + dimStyle.Render(i18n.T(lang, "common.press_enter")) + "\n"
	}
	lines := ""
	for i, s := range m.servers {
		cursor := "  "
		label := fmt.Sprintf("%s  (%s@%s:%d)", s.Name, s.Username, s.IP, s.Port)
		if i == m.pickCur {
			cursor = "▸ "
			label = selectedStyle.Render(label)
		}
		lines += cursor + label + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "menu.hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(lines) + "\n" + hint + "\n"
}

// ---- Sunucu formu (ekle/düzenle) ----

const (
	fName = iota
	fIP
	fHostname
	fPort
	fUsername
	fKey
	fGroup
	fCount
)

type serverForm struct {
	editing bool
	id      int64
	inputs  []textinput.Model
	focus   int
	keys    []model.SSHKey
	groups  []model.Group
	lang    string
	errMsg  string
}

func newServerForm(lang string, existing *model.ServerView, keys []model.SSHKey, groups []model.Group) serverForm {
	f := serverForm{
		lang:   lang,
		keys:   keys,
		groups: groups,
		inputs: make([]textinput.Model, fCount),
	}
	for i := range f.inputs {
		ti := textinput.New()
		ti.CharLimit = 128
		ti.Width = 40
		f.inputs[i] = ti
	}
	if existing != nil {
		f.editing = true
		f.id = existing.ID
		f.inputs[fName].SetValue(existing.Name)
		f.inputs[fIP].SetValue(existing.IP)
		f.inputs[fHostname].SetValue(existing.Hostname)
		f.inputs[fPort].SetValue(strconv.Itoa(existing.Port))
		f.inputs[fUsername].SetValue(existing.Username)
		f.inputs[fKey].SetValue(existing.KeyName)
		f.inputs[fGroup].SetValue(existing.GroupNames)
	} else {
		f.inputs[fPort].SetValue("22")
	}
	f.focus = 0
	f.refocus()
	return f
}

func (f *serverForm) refocus() {
	for i := range f.inputs {
		if i == f.focus {
			f.inputs[i].Focus()
		} else {
			f.inputs[i].Blur()
		}
	}
}

func (m appModel) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.state = stMenu
			return m, nil
		case "tab", "down":
			m.form.focus = (m.form.focus + 1) % len(m.form.inputs)
			m.form.refocus()
			return m, nil
		case "shift+tab", "up":
			m.form.focus = (m.form.focus - 1 + len(m.form.inputs)) % len(m.form.inputs)
			m.form.refocus()
			return m, nil
		case "enter":
			return m.saveForm()
		}
	}
	var cmd tea.Cmd
	m.form.inputs[m.form.focus], cmd = m.form.inputs[m.form.focus].Update(msg)
	return m, cmd
}

func (m appModel) saveForm() (tea.Model, tea.Cmd) {
	lang := m.sess.Lang
	name := strings.TrimSpace(m.form.inputs[fName].Value())
	ip := strings.TrimSpace(m.form.inputs[fIP].Value())
	hostname := strings.TrimSpace(m.form.inputs[fHostname].Value())
	username := strings.TrimSpace(m.form.inputs[fUsername].Value())
	portStr := strings.TrimSpace(m.form.inputs[fPort].Value())
	keyName := strings.TrimSpace(m.form.inputs[fKey].Value())

	if name == "" {
		return m.formError(i18n.T(lang, "servers.invalid", i18n.T(lang, "servers.field_name"))), nil
	}
	if ip == "" {
		return m.formError(i18n.T(lang, "servers.invalid", i18n.T(lang, "servers.field_ip"))), nil
	}
	if username == "" {
		return m.formError(i18n.T(lang, "servers.invalid", i18n.T(lang, "servers.field_username"))), nil
	}
	port := 22
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return m.formError(i18n.T(lang, "servers.invalid", i18n.T(lang, "servers.field_port"))), nil
		}
		port = p
	}
	var keyID int64
	if keyName != "" {
		found := false
		for _, k := range m.form.keys {
			if k.Name == keyName {
				keyID = k.ID
				found = true
				break
			}
		}
		if !found {
			return m.formError(i18n.T(lang, "servers.invalid", i18n.T(lang, "servers.field_key"))), nil
		}
	}

	// "Grup" alanı virgülle ayrılmış birden çok grup adı içerebilir.
	groupIDs, ok := m.resolveGroupIDs(m.form.inputs[fGroup].Value())
	if !ok {
		return m.formError(i18n.T(lang, "servers.invalid", i18n.T(lang, "servers.field_group"))), nil
	}

	srv := model.Server{
		ID:       m.form.id,
		Name:     name,
		Hostname: hostname,
		IP:       ip,
		Port:     port,
		Username: username,
		SSHKeyID: keyID,
	}

	var err error
	action := audit.ActionServerAdd
	serverID := srv.ID
	if m.form.editing {
		err = m.deps.Store.UpdateServer(srv)
		action = audit.ActionServerEdit
	} else {
		serverID, err = m.deps.Store.CreateServer(srv)
	}
	if err != nil {
		return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stMenu), nil
	}
	if err := m.deps.Store.SetServerGroups(serverID, groupIDs); err != nil {
		return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stMenu), nil
	}
	m.deps.Audit.Event(m.sess.UserID, m.sess.Username, action, srv.Name, m.sess.IP, "")
	return m.showMessage(i18n.T(lang, "servers.saved"), true, stMenu), nil
}

// resolveGroupIDs, virgülle ayrılmış grup adlarını ID listesine çevirir.
// Bilinmeyen bir grup adı varsa ok=false döner.
func (m appModel) resolveGroupIDs(raw string) ([]int64, bool) {
	var ids []int64
	for _, part := range strings.Split(raw, ",") {
		nm := strings.TrimSpace(part)
		if nm == "" {
			continue
		}
		found := false
		for _, g := range m.form.groups {
			if g.Name == nm {
				ids = append(ids, g.ID)
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return ids, true
}

func (m appModel) formError(msg string) appModel {
	m.form.errMsg = msg
	return m
}

func (m appModel) viewForm() string {
	lang := m.sess.Lang
	titleKey := "servers.add_title"
	if m.form.editing {
		titleKey = "servers.edit_title"
	}
	title := titleStyle.Render(i18n.T(lang, titleKey))

	labels := []string{
		i18n.T(lang, "servers.field_name"),
		i18n.T(lang, "servers.field_ip"),
		i18n.T(lang, "servers.field_hostname"),
		i18n.T(lang, "servers.field_port"),
		i18n.T(lang, "servers.field_username"),
		i18n.T(lang, "servers.field_key"),
		i18n.T(lang, "servers.field_group"),
	}
	body := ""
	for i, ti := range m.form.inputs {
		marker := "  "
		label := labels[i]
		if i == m.form.focus {
			marker = "▸ "
			label = selectedStyle.Render(label)
		}
		body += fmt.Sprintf("%s%-26s %s\n", marker, label, ti.View())
	}
	if len(m.form.keys) > 0 {
		names := make([]string, 0, len(m.form.keys))
		for _, k := range m.form.keys {
			names = append(names, k.Name)
		}
		body += "\n" + dimStyle.Render("Anahtarlar / Keys: "+strings.Join(names, ", ")) + "\n"
	}
	if len(m.form.groups) > 0 {
		names := make([]string, 0, len(m.form.groups))
		for _, g := range m.form.groups {
			names = append(names, g.Name)
		}
		body += dimStyle.Render("Gruplar / Groups: "+strings.Join(names, ", ")) + "\n"
	}
	if m.form.errMsg != "" {
		body += errStyle.Render(m.form.errMsg) + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "servers.form_hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(body) + "\n" + hint + "\n"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
