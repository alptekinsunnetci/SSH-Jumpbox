// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package tui

import (
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"jumpbox/internal/audit"
	"jumpbox/internal/crypto"
	"jumpbox/internal/db"
	"jumpbox/internal/model"
)

func testDeps(t *testing.T) (Deps, *db.Store) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	vault, _ := crypto.NewVault(make([]byte, 32))
	auditor, err := audit.New(store, filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { auditor.Close() })

	return Deps{Store: store, Audit: auditor, Vault: vault, Issuer: "JumpBox", BcryptCost: 4}, store
}

func key(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// TestUserGroupToggleViaTUI, admin'in Kullanıcılar → g ekranından bir kullanıcıya
// grup erişimi verip kaldırmasının veritabanına yansıdığını doğrular.
func TestUserGroupToggleViaTUI(t *testing.T) {
	deps, store := testDeps(t)
	bob, _ := store.CreateUser(model.User{Username: "bob", PasswordHash: "h", TOTPSecret: "x"})
	gid, _ := store.CreateGroup("prod")

	m := newAppModel(deps, Session{UserID: 1, Username: "admin", Lang: "tr", IsAdmin: true, Width: 80, Height: 24})
	m.loadUsers()
	m.userCur = 0
	m.state = stUsers

	// 'g' → grup erişim ekranı açılmalı, doğru kullanıcı seçili olmalı.
	next, _ := m.Update(key("g"))
	m = next.(appModel)
	if m.state != stUserGroups {
		t.Fatalf("'g' sonrası stUserGroups bekleniyordu, got %d", m.state)
	}
	if m.manageUser.ID != bob {
		t.Fatalf("manageUser bob olmalı, got %d", m.manageUser.ID)
	}
	if len(m.ugGroups) != 1 {
		t.Fatalf("1 grup bekleniyordu, got %d", len(m.ugGroups))
	}

	// Boşluk → grup erişimi verilmeli (DB'ye yazılmalı).
	next, _ = m.Update(key(" "))
	m = next.(appModel)
	ids, _ := store.ListUserGroupIDs(bob)
	if !ids[gid] {
		t.Fatal("boşluktan sonra kullanıcı gruba eklenmiş olmalı (DB)")
	}
	if !m.ugSet[gid] {
		t.Fatal("ekranda [x] işareti (ugSet) güncellenmeliydi")
	}

	// Tekrar boşluk → erişim kaldırılmalı.
	next, _ = m.Update(key(" "))
	m = next.(appModel)
	ids, _ = store.ListUserGroupIDs(bob)
	if ids[gid] {
		t.Fatal("ikinci boşluktan sonra grup erişimi kaldırılmalıydı")
	}
}

// TestServerGroupAssignViaForm, sunucu formundan virgülle çoklu grup atamasının
// kaydedildiğini doğrular.
func TestServerGroupAssignViaForm(t *testing.T) {
	deps, store := testDeps(t)
	g1, _ := store.CreateGroup("prod")
	g2, _ := store.CreateGroup("dev")
	srvID, _ := store.CreateServer(model.Server{Name: "web", IP: "10.0.0.1", Port: 22, Username: "u"})

	m := newAppModel(deps, Session{UserID: 1, Username: "admin", Lang: "tr", IsAdmin: true, Width: 80, Height: 24})
	view := model.ServerView{Server: model.Server{ID: srvID, Name: "web", IP: "10.0.0.1", Port: 22, Username: "u"}}
	m.form = newServerForm("tr", &view, nil, []model.Group{{ID: g1, Name: "prod"}, {ID: g2, Name: "dev"}})
	m.state = stForm
	m.form.inputs[fGroup].SetValue("prod, dev")

	if _, ok := m.resolveGroupIDs("prod, dev"); !ok {
		t.Fatal("geçerli grup adları çözülmeliydi")
	}
	if _, ok := m.resolveGroupIDs("prod, yok"); ok {
		t.Fatal("bilinmeyen grup reddedilmeliydi")
	}

	// saveForm çağrısı: grupları kaydetmeli.
	if _, _ = m.saveForm(); true {
		names, _ := store.ListServerGroupNames(srvID)
		if len(names) != 2 {
			t.Fatalf("sunucuya 2 grup atanmalıydı, got %v", names)
		}
	}
}
