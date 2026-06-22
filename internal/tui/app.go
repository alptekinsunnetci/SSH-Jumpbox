// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package tui, JumpBox'ın klavyeyle yönetilen terminal arayüzünü (Bubble Tea)
// sağlar. Tüm kullanıcıya dönük metinler i18n kataloğundan gelir.
package tui

import (
	"context"
	"io"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"jumpbox/internal/audit"
	"jumpbox/internal/crypto"
	"jumpbox/internal/db"
	"jumpbox/internal/i18n"
	"jumpbox/internal/model"
)

// Action, menünün dış akışa (oturum döngüsüne) bildirdiği sonucu belirtir.
type Action int

const (
	// ActionNone, oturumun sonlandırılması gerektiğini belirtir (varsayılan).
	ActionNone Action = iota
	// ActionExit, kullanıcının çıkış seçtiğini belirtir.
	ActionExit
	// ActionConnect, kullanıcının bir sunucuya bağlanmak istediğini belirtir.
	ActionConnect
)

// Result, RunMenu'nün döndürdüğü sonuçtur.
type Result struct {
	Action Action
	Server model.Server
}

// Deps, TUI'nin ihtiyaç duyduğu bağımlılıklardır.
type Deps struct {
	Store      *db.Store
	Audit      *audit.Logger
	Vault      *crypto.Vault
	Issuer     string
	BcryptCost int
}

// Winsizer, terminal boyut değişikliklerine abone olunmasını sağlar
// (w = sütun, h = satır).
type Winsizer interface {
	Subscribe(func(w, h int))
}

// Session, tek bir kullanıcı oturumunun bağlamıdır.
type Session struct {
	UserID   int64
	Username string
	Lang     string
	IP       string
	IsAdmin  bool
	Width    int
	Height   int
	Input    io.Reader
	Output   io.Writer
	Win      Winsizer
}

// state, TUI'nin ekran durumudur.
type state int

const (
	stMenu state = iota
	stList
	stForm    // sunucu ekle/düzenle
	stPick    // bağlan/düzenle/sil için sunucu seçimi
	stConfirm // genel silme onayı
	stLogs
	stLang
	stMessage
	stKeys       // SSH anahtarları listesi
	stKeyForm    // yeni anahtar adı girişi
	stUsers      // kullanıcı listesi
	stUserForm   // yeni kullanıcı formu
	stUserIPs    // seçili kullanıcının izinli IP'leri
	stIPForm     // yeni IP girişi
	stGroups     // grup listesi
	stGroupForm  // yeni grup adı girişi
	stUserGroups // seçili kullanıcının grup erişimleri
)

// pickPurpose, sunucu seçim ekranının amacını belirtir.
type pickPurpose int

const (
	pickConnect pickPurpose = iota
	pickEdit
	pickDelete
)

// confirmKind, genel silme onayının neyi sildiğini belirtir.
type confirmKind int

const (
	confirmServer confirmKind = iota
	confirmKey
	confirmUser
	confirmIP
	confirmGroup
)

// inputKind, tek alanlı girişin amacını belirtir.
type inputKind int

const (
	inputKeyName inputKind = iota
	inputIP
	inputGroupName
)

type appModel struct {
	deps   Deps
	sess   Session
	width  int
	height int

	state   state
	menuCur int
	langCur int

	// sunucu listesi (list/pick)
	servers []model.ServerView
	pickCur int
	purpose pickPurpose

	// sunucu formu (ekle/düzenle)
	form serverForm

	// SSH anahtarları
	sshKeys []model.SSHKey
	keyCur  int

	// kullanıcılar
	users   []model.User
	userCur int

	// gruplar
	groups   []model.Group
	groupCur int

	// seçili kullanıcının IP yönetimi
	manageUser model.User
	userIPs    []string
	ipCur      int

	// seçili kullanıcının grup erişim yönetimi
	ugGroups []model.Group
	ugSet    map[int64]bool
	ugCur    int

	// tek alanlı giriş (anahtar adı / IP)
	input     textinput.Model
	inputKind inputKind

	// kullanıcı formu
	uform userForm

	// genel silme onayı
	confirmKind   confirmKind
	confirmName   string
	confirmID     int64
	confirmIP     string
	confirmReturn state

	// loglar
	logs    []model.AuditEntry
	logsTop int

	// mesaj ekranı
	message       string
	messageOK     bool
	messageReturn state

	// sonuç
	action Action
	chosen model.Server
}

// RunMenu, menü programını verilen oturum üzerinde çalıştırır ve kullanıcının
// seçtiği eylemi ile (değişmiş olabilecek) dilini döndürür.
func RunMenu(ctx context.Context, deps Deps, sess Session) (Result, string) {
	m := newAppModel(deps, sess)
	p := tea.NewProgram(
		m,
		tea.WithContext(ctx),
		tea.WithInput(sess.Input),
		tea.WithOutput(sess.Output),
		tea.WithAltScreen(),
		tea.WithoutSignalHandler(),
	)

	// Terminal boyut değişikliklerini programa ilet (deadlock'u önlemek için
	// her gönderim ayrı goroutine'de yapılır).
	if sess.Win != nil {
		sess.Win.Subscribe(func(w, h int) {
			go p.Send(tea.WindowSizeMsg{Width: w, Height: h})
		})
		defer sess.Win.Subscribe(nil)
	}

	final, err := p.Run()
	if err != nil {
		return Result{Action: ActionNone}, sess.Lang
	}
	fm, ok := final.(appModel)
	if !ok {
		return Result{Action: ActionNone}, sess.Lang
	}
	return Result{Action: fm.action, Server: fm.chosen}, fm.sess.Lang
}

func newAppModel(deps Deps, sess Session) appModel {
	if sess.Width <= 0 {
		sess.Width = 80
	}
	if sess.Height <= 0 {
		sess.Height = 24
	}
	sess.Lang = i18n.Normalize(sess.Lang)
	return appModel{
		deps:    deps,
		sess:    sess,
		width:   sess.Width,
		height:  sess.Height,
		state:   stMenu,
		langCur: langIndex(sess.Lang),
	}
}

func (m appModel) Init() tea.Cmd { return nil }

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.action = ActionExit
			return m, tea.Quit
		}
		return m.handleKey(msg)
	}
	// Metin girişli ekranlarda diğer mesajları input'a ilet.
	switch m.state {
	case stForm:
		return m.updateForm(msg)
	case stUserForm:
		return m.updateUserForm(msg)
	case stKeyForm, stIPForm, stGroupForm:
		return m.updateInput(msg)
	}
	return m, nil
}

func (m appModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.state {
	case stMenu:
		return m.updateMenu(msg)
	case stList:
		return m.updateList(msg)
	case stPick:
		return m.updatePick(msg)
	case stForm:
		return m.updateForm(msg)
	case stConfirm:
		return m.updateConfirm(msg)
	case stLogs:
		return m.updateLogs(msg)
	case stLang:
		return m.updateLang(msg)
	case stMessage:
		return m.updateMessage(msg)
	case stKeys:
		return m.updateKeys(msg)
	case stKeyForm:
		return m.updateInput(msg)
	case stUsers:
		return m.updateUsers(msg)
	case stUserForm:
		return m.updateUserForm(msg)
	case stUserIPs:
		return m.updateUserIPs(msg)
	case stIPForm:
		return m.updateInput(msg)
	case stGroups:
		return m.updateGroups(msg)
	case stGroupForm:
		return m.updateInput(msg)
	case stUserGroups:
		return m.updateUserGroups(msg)
	}
	return m, nil
}

func (m appModel) View() string {
	switch m.state {
	case stMenu:
		return m.viewMenu()
	case stList:
		return m.viewList()
	case stPick:
		return m.viewPick()
	case stForm:
		return m.viewForm()
	case stConfirm:
		return m.viewConfirm()
	case stLogs:
		return m.viewLogs()
	case stLang:
		return m.viewLang()
	case stMessage:
		return m.viewMessage()
	case stKeys:
		return m.viewKeys()
	case stKeyForm, stIPForm, stGroupForm:
		return m.viewInput()
	case stUsers:
		return m.viewUsers()
	case stUserForm:
		return m.viewUserForm()
	case stUserIPs:
		return m.viewUserIPs()
	case stGroups:
		return m.viewGroups()
	case stUserGroups:
		return m.viewUserGroups()
	}
	return ""
}

// ---- Menü ----

type menuID int

const (
	miList menuID = iota
	miAdd
	miEdit
	miDelete
	miConnect
	miKeys
	miUsers
	miGroups
	miLogs
	miLang
	miExit
)

// menuItems, kullanıcının yetkisine göre menü öğelerini döndürür (admin'e özel
// öğeler yalnızca yöneticilere gösterilir).
func (m appModel) menuItems() []menuID {
	// Admin olmayan kullanıcılar yalnızca izinli sunucuları listeleyip bağlanabilir.
	if !m.sess.IsAdmin {
		return []menuID{miList, miConnect, miLogs, miLang, miExit}
	}
	return []menuID{miList, miAdd, miEdit, miDelete, miConnect, miKeys, miUsers, miGroups, miLogs, miLang, miExit}
}

func menuLabel(lang string, id menuID) string {
	switch id {
	case miList:
		return i18n.T(lang, "menu.list")
	case miAdd:
		return i18n.T(lang, "menu.add")
	case miEdit:
		return i18n.T(lang, "menu.edit")
	case miDelete:
		return i18n.T(lang, "menu.delete")
	case miConnect:
		return i18n.T(lang, "menu.connect")
	case miKeys:
		return i18n.T(lang, "menu.keys")
	case miUsers:
		return i18n.T(lang, "menu.users")
	case miGroups:
		return i18n.T(lang, "menu.groups")
	case miLogs:
		return i18n.T(lang, "menu.logs")
	case miLang:
		return i18n.T(lang, "menu.language")
	case miExit:
		return i18n.T(lang, "menu.exit")
	}
	return ""
}

func (m appModel) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	items := m.menuItems()
	switch msg.String() {
	case "up", "k":
		if m.menuCur > 0 {
			m.menuCur--
		}
	case "down", "j":
		if m.menuCur < len(items)-1 {
			m.menuCur++
		}
	case "q":
		m.action = ActionExit
		return m, tea.Quit
	case "enter", " ":
		return m.activateMenu(items[m.menuCur])
	}
	return m, nil
}

func (m appModel) activateMenu(id menuID) (tea.Model, tea.Cmd) {
	switch id {
	case miList:
		m.loadServers()
		m.state = stList
	case miAdd:
		m.form = newServerForm(m.sess.Lang, nil, m.loadKeys(), m.loadGroupList())
		m.state = stForm
	case miEdit:
		m.loadServers()
		m.purpose = pickEdit
		m.pickCur = 0
		m.state = stPick
	case miDelete:
		m.loadServers()
		m.purpose = pickDelete
		m.pickCur = 0
		m.state = stPick
	case miConnect:
		m.loadServers()
		m.purpose = pickConnect
		m.pickCur = 0
		m.state = stPick
	case miKeys:
		m.loadSSHKeys()
		m.keyCur = 0
		m.state = stKeys
	case miUsers:
		m.loadUsers()
		m.userCur = 0
		m.state = stUsers
	case miGroups:
		m.loadGroups()
		m.groupCur = 0
		m.state = stGroups
	case miLogs:
		m.loadLogs()
		m.logsTop = 0
		m.state = stLogs
	case miLang:
		m.langCur = langIndex(m.sess.Lang)
		m.state = stLang
	case miExit:
		m.action = ActionExit
		return m, tea.Quit
	}
	return m, nil
}

func (m appModel) viewMenu() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "app.title"))
	welcome := dimStyle.Render(i18n.T(lang, "app.welcome_user", m.sess.Username))

	lines := ""
	for i, id := range m.menuItems() {
		cursor := "  "
		label := menuLabel(lang, id)
		if i == m.menuCur {
			cursor = "▸ "
			label = selectedStyle.Render(label)
		}
		lines += cursor + label + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "menu.hint"))
	body := boxStyle.Render(lines)
	return "\n" + title + "\n" + welcome + "\n\n" + body + "\n" + hint + "\n"
}

// ---- Genel silme onayı ----

func (m appModel) askConfirm(kind confirmKind, id int64, name, ip string, ret state) appModel {
	m.confirmKind = kind
	m.confirmID = id
	m.confirmName = name
	m.confirmIP = ip
	m.confirmReturn = ret
	m.state = stConfirm
	return m
}

func (m appModel) updateConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	lang := m.sess.Lang
	switch lowerKey(msg) {
	case "e", "y", "enter":
		switch m.confirmKind {
		case confirmServer:
			if err := m.deps.Store.DeleteServer(m.confirmID); err != nil {
				return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stMenu), nil
			}
			m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionServerDel, m.confirmName, m.sess.IP, "")
			return m.showMessage(i18n.T(lang, "servers.deleted"), true, stMenu), nil
		case confirmKey:
			if err := m.deps.Store.DeleteSSHKey(m.confirmID); err != nil {
				return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stKeys), nil
			}
			m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionKeyDel, m.confirmName, m.sess.IP, "")
			m.loadSSHKeys()
			return m.showMessage(i18n.T(lang, "keys.deleted"), true, stKeys), nil
		case confirmUser:
			if err := m.deps.Store.DeleteUser(m.confirmID); err != nil {
				return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stUsers), nil
			}
			m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionUserDel, m.confirmName, m.sess.IP, "")
			m.loadUsers()
			return m.showMessage(i18n.T(lang, "users.deleted"), true, stUsers), nil
		case confirmIP:
			if err := m.deps.Store.RemoveAllowedIP(m.manageUser.ID, m.confirmIP); err != nil {
				return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stUserIPs), nil
			}
			m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionIPDel, m.manageUser.Username, m.sess.IP, m.confirmIP)
			m.loadUserIPs()
			return m.showMessage(i18n.T(lang, "ips.removed"), true, stUserIPs), nil
		case confirmGroup:
			if err := m.deps.Store.DeleteGroup(m.confirmID); err != nil {
				return m.showMessage(i18n.T(lang, "common.error", err.Error()), false, stGroups), nil
			}
			m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionGroupDel, m.confirmName, m.sess.IP, "")
			m.loadGroups()
			return m.showMessage(i18n.T(lang, "groups.deleted"), true, stGroups), nil
		}
	case "h", "n", "esc", "q":
		m.state = m.confirmReturn
	}
	return m, nil
}

func (m appModel) viewConfirm() string {
	lang := m.sess.Lang
	var q string
	switch m.confirmKind {
	case confirmKey:
		q = i18n.T(lang, "keys.delete_confirm", m.confirmName)
	case confirmUser:
		q = i18n.T(lang, "users.delete_confirm", m.confirmName)
	case confirmIP:
		q = i18n.T(lang, "servers.delete_confirm", m.confirmIP)
	case confirmGroup:
		q = i18n.T(lang, "groups.delete_confirm", m.confirmName)
	default:
		q = i18n.T(lang, "servers.delete_confirm", m.confirmName)
	}
	return "\n" + boxStyle.Render(errStyle.Render(q)) + "\n"
}

// ---- Mesaj ekranı ----

func (m appModel) showMessage(text string, ok bool, ret state) appModel {
	m.message = text
	m.messageOK = ok
	m.messageReturn = ret
	m.state = stMessage
	return m
}

func (m appModel) updateMessage(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc", " ", "q":
		m.state = m.messageReturn
	}
	return m, nil
}

func (m appModel) viewMessage() string {
	lang := m.sess.Lang
	style := okStyle
	if !m.messageOK {
		style = errStyle
	}
	body := style.Render(m.message) + "\n\n" + dimStyle.Render(i18n.T(lang, "common.press_enter"))
	return "\n" + boxStyle.Render(body) + "\n"
}

// ---- Dil seçimi ----

func langIndex(lang string) int {
	for i, l := range i18n.Available() {
		if l == lang {
			return i
		}
	}
	return 0
}

func (m appModel) updateLang(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	langs := i18n.Available()
	switch msg.String() {
	case "up", "k":
		if m.langCur > 0 {
			m.langCur--
		}
	case "down", "j":
		if m.langCur < len(langs)-1 {
			m.langCur++
		}
	case "esc", "q":
		m.state = stMenu
	case "enter", " ":
		newLang := langs[m.langCur]
		if newLang != m.sess.Lang {
			m.sess.Lang = newLang
			_ = m.deps.Store.SetLanguage(m.sess.UserID, newLang)
			m.deps.Audit.Event(m.sess.UserID, m.sess.Username, audit.ActionLangChange, "", m.sess.IP, newLang)
		}
		return m.showMessage(i18n.T(m.sess.Lang, "lang.changed"), true, stMenu), nil
	}
	return m, nil
}

func (m appModel) viewLang() string {
	lang := m.sess.Lang
	title := titleStyle.Render(i18n.T(lang, "lang.title"))
	lines := ""
	for i, l := range i18n.Available() {
		cursor := "  "
		label := i18n.T(lang, "lang."+l)
		if i == m.langCur {
			cursor = "▸ "
			label = selectedStyle.Render(label)
		}
		lines += cursor + label + "\n"
	}
	hint := dimStyle.Render(i18n.T(lang, "menu.hint"))
	return "\n" + title + "\n\n" + boxStyle.Render(lines) + "\n" + hint + "\n"
}

// loadKeys, mevcut SSH anahtarlarını döndürür (sunucu formu için).
func (m *appModel) loadKeys() []model.SSHKey {
	keys, _ := m.deps.Store.ListSSHKeys()
	return keys
}

// loadGroupList, mevcut grupları döndürür (sunucu formu için).
func (m *appModel) loadGroupList() []model.Group {
	groups, _ := m.deps.Store.ListGroups()
	return groups
}

// lowerKey, bir tuş mesajını küçük harfe çevirir.
func lowerKey(msg tea.KeyMsg) string {
	s := msg.String()
	if len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' {
		return string(s[0] + 32)
	}
	return s
}
