// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

import (
	"path/filepath"
	"testing"

	"jumpbox/internal/model"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUserCRUD(t *testing.T) {
	s := newStore(t)
	id, err := s.CreateUser(model.User{
		Username:     "alice",
		PasswordHash: "hash",
		TOTPSecret:   "SECRET",
		Language:     "tr",
		IsAdmin:      true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := s.GetUserByUsername("alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if u.ID != id || !u.IsAdmin || u.TOTPEnrolled || u.Language != "tr" {
		t.Fatalf("kullanıcı alanları beklenmedik: %+v", u)
	}
	if err := s.SetTOTPEnrolled(id, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLanguage(id, "en"); err != nil {
		t.Fatal(err)
	}
	u, _ = s.GetUserByID(id)
	if !u.TOTPEnrolled || u.Language != "en" {
		t.Fatalf("güncelleme yansımadı: %+v", u)
	}

	if _, err := s.GetUserByUsername("yok"); err != ErrNotFound {
		t.Fatalf("ErrNotFound bekleniyordu, got %v", err)
	}
}

func TestServerWithKey(t *testing.T) {
	s := newStore(t)
	keyID, err := s.CreateSSHKey(model.SSHKey{
		Name:                "anahtar1",
		PrivateKeyEncrypted: []byte{1, 2, 3},
		PublicKey:           "ssh-ed25519 AAAA...",
	})
	if err != nil {
		t.Fatalf("CreateSSHKey: %v", err)
	}
	srvID, err := s.CreateServer(model.Server{
		Name:     "web-01",
		IP:       "10.0.0.1",
		Port:     22,
		Username: "deploy",
		SSHKeyID: keyID,
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	list, err := s.ListServers()
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(list) != 1 || list[0].KeyName != "anahtar1" || list[0].SSHKeyID != keyID {
		t.Fatalf("liste beklenmedik: %+v", list)
	}

	srv, err := s.GetServer(srvID)
	if err != nil || srv.SSHKeyID != keyID {
		t.Fatalf("GetServer: %+v err=%v", srv, err)
	}

	if err := s.DeleteServer(srvID); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListServers()
	if len(list) != 0 {
		t.Fatalf("silme sonrası liste boş olmalı: %+v", list)
	}
}

func TestAllowedIPsAndAudit(t *testing.T) {
	s := newStore(t)
	uid, _ := s.CreateUser(model.User{Username: "bob", PasswordHash: "h", TOTPSecret: "x"})

	if err := s.AddAllowedIP(uid, "10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	_ = s.AddAllowedIP(uid, "10.0.0.0/8") // idempotent
	ips, _ := s.ListAllowedIPs(uid)
	if len(ips) != 1 || ips[0] != "10.0.0.0/8" {
		t.Fatalf("izinli IP listesi beklenmedik: %v", ips)
	}

	if err := s.AddAudit(model.AuditEntry{UserID: uid, Username: "bob", Action: "LOGIN_OK", IPAddress: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	logs, _ := s.ListAuditByUser(uid, 10)
	if len(logs) != 1 || logs[0].Action != "LOGIN_OK" {
		t.Fatalf("audit kaydı beklenmedik: %+v", logs)
	}
}

func TestGroupAccessControl(t *testing.T) {
	s := newStore(t)

	g1, err := s.CreateGroup("prod")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	g2, _ := s.CreateGroup("dev")

	keyID, _ := s.CreateSSHKey(model.SSHKey{Name: "k", PrivateKeyEncrypted: []byte{1}, PublicKey: "p"})
	s1, _ := s.CreateServer(model.Server{Name: "prod-web", IP: "10.0.0.1", Port: 22, Username: "u", SSHKeyID: keyID})
	s2, _ := s.CreateServer(model.Server{Name: "dev-web", IP: "10.0.1.1", Port: 22, Username: "u", SSHKeyID: keyID})
	sBoth, _ := s.CreateServer(model.Server{Name: "shared", IP: "10.0.3.1", Port: 22, Username: "u", SSHKeyID: keyID})
	sUngrouped, _ := s.CreateServer(model.Server{Name: "lonely", IP: "10.0.2.1", Port: 22, Username: "u", SSHKeyID: keyID})

	// Çoklu grup: prod-web -> {prod}, dev-web -> {dev}, shared -> {prod, dev}.
	if err := s.SetServerGroups(s1, []int64{g1}); err != nil {
		t.Fatal(err)
	}
	_ = s.SetServerGroups(s2, []int64{g2})
	_ = s.SetServerGroups(sBoth, []int64{g1, g2})

	uid, _ := s.CreateUser(model.User{Username: "carol", PasswordHash: "h", TOTPSecret: "x"})

	// Henüz grup yok: hiçbir sunucu görünmez/erişilmez.
	if list, _ := s.ListServersForUser(uid); len(list) != 0 {
		t.Fatalf("grup verilmeden 0 sunucu beklenir, got %d", len(list))
	}

	// prod grubuna erişim ver -> prod-web ve shared görünür (dev-web görünmez).
	if err := s.AddUserGroup(uid, g1); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListServersForUser(uid)
	if len(list) != 2 {
		t.Fatalf("prod erişimiyle 2 sunucu (prod-web, shared) beklenir: %+v", list)
	}
	if ok, _ := s.UserCanAccessServer(uid, s1); !ok {
		t.Fatal("s1'e erişebilmeliydi")
	}
	if ok, _ := s.UserCanAccessServer(uid, sBoth); !ok {
		t.Fatal("çoklu gruplu shared sunucuya erişebilmeliydi")
	}
	if ok, _ := s.UserCanAccessServer(uid, s2); ok {
		t.Fatal("s2'ye (dev) erişememeliydi")
	}
	if ok, _ := s.UserCanAccessServer(uid, sUngrouped); ok {
		t.Fatal("gruba atanmamış sunucuya erişememeliydi")
	}

	// GroupNames birleşik gösterimi.
	for _, v := range list {
		if v.ID == sBoth && v.GroupNames == "" {
			t.Fatal("shared sunucu için grup adları boş olmamalı")
		}
	}

	// Admin görünümü: tüm sunucular.
	if all, _ := s.ListServers(); len(all) != 4 {
		t.Fatalf("admin 4 sunucu görmeli, got %d", len(all))
	}

	// Grubu silince üyelikler kalkar; prod erişimi yalnızca dev'i bırakır.
	if err := s.DeleteGroup(g1); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListServersForUser(uid); len(list) != 0 {
		t.Fatalf("prod grubu silinince (kullanıcı yalnız prod'a sahipti) 0 sunucu beklenir, got %d", len(list))
	}
}

func TestKnownHostsTOFU(t *testing.T) {
	s := newStore(t)
	if _, err := s.GetHostKey("h:22"); err != ErrNotFound {
		t.Fatalf("başta ErrNotFound bekleniyordu: %v", err)
	}
	if err := s.SetHostKey("h:22", "SHA256:abc"); err != nil {
		t.Fatal(err)
	}
	fp, err := s.GetHostKey("h:22")
	if err != nil || fp != "SHA256:abc" {
		t.Fatalf("fingerprint beklenmedik: %q err=%v", fp, err)
	}
}
