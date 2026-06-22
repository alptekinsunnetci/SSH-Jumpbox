// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package audit, denetim olaylarını hem JSON satır dosyasına hem de veritabanına
// yazar. Dosya formatı, makine tarafından kolayca işlenebilen tek satırlık JSON'dur.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"jumpbox/internal/model"
)

// Eylem (action) sabitleri.
const (
	ActionLoginOK    = "LOGIN_OK"
	ActionLoginFail  = "LOGIN_FAIL"
	ActionLoginBan   = "LOGIN_BANNED"
	ActionIPDenied   = "IP_DENIED"
	ActionMenuOpen   = "MENU_OPEN"
	ActionServerAdd  = "SERVER_ADD"
	ActionServerEdit = "SERVER_EDIT"
	ActionServerDel  = "SERVER_DELETE"
	ActionConnect    = "CONNECT_SERVER"
	ActionSessionEnd = "SESSION_END"
	ActionLangChange = "LANG_CHANGE"
	ActionKeyAdd     = "KEY_ADD"
	ActionKeyDel     = "KEY_DELETE"
	ActionUserAdd    = "USER_ADD"
	ActionUserDel    = "USER_DELETE"
	ActionIPAdd      = "IP_ADD"
	ActionIPDel      = "IP_DELETE"
	ActionGroupAdd   = "GROUP_ADD"
	ActionGroupDel   = "GROUP_DELETE"
	ActionGroupGrant = "GROUP_GRANT"
	ActionGroupRevk  = "GROUP_REVOKE"
	ActionAccessDeny = "ACCESS_DENIED"
)

// Store, audit kayıtlarının yazılacağı veritabanı arayüzüdür.
type Store interface {
	AddAudit(model.AuditEntry) error
}

// Entry, JSON dosyasına yazılan denetim kaydıdır (spec'teki alan adlarıyla uyumlu).
type Entry struct {
	User   string    `json:"user"`
	Action string    `json:"action"`
	Server string    `json:"server,omitempty"`
	IP     string    `json:"ip"`
	Detail string    `json:"detail,omitempty"`
	Time   time.Time `json:"time"`

	// userID dosyaya yazılmaz; yalnızca DB ilişkisi için kullanılır.
	userID int64
}

// Logger, eşzamanlı güvenli (thread-safe) denetim kaydedicidir.
type Logger struct {
	store Store
	mu    sync.Mutex
	file  *os.File
	enc   *json.Encoder
}

// New, verilen dosyaya append modunda yazan bir Logger oluşturur.
func New(store Store, path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{store: store, file: f, enc: json.NewEncoder(f)}, nil
}

// Close, log dosyasını kapatır.
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Event, bir denetim olayını dosyaya ve veritabanına yazar. Hata durumunda
// sessizce devam eder (denetim, ana akışı bloklamamalıdır).
func (l *Logger) Event(userID int64, username, action, server, ip, detail string) {
	e := Entry{
		User:   username,
		Action: action,
		Server: server,
		IP:     ip,
		Detail: detail,
		Time:   time.Now().UTC(),
		userID: userID,
	}
	l.mu.Lock()
	if l.enc != nil {
		_ = l.enc.Encode(e) // her satır kendi JSON nesnesi (NDJSON)
	}
	l.mu.Unlock()

	if l.store != nil {
		_ = l.store.AddAudit(model.AuditEntry{
			UserID:       userID,
			Username:     username,
			Action:       action,
			TargetServer: server,
			IPAddress:    ip,
			Detail:       detail,
			Timestamp:    e.Time,
		})
	}
}
