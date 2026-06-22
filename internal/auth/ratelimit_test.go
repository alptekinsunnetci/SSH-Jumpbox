// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package auth

import (
	"path/filepath"
	"testing"
	"time"

	"jumpbox/internal/db"
)

func newTestStore(t *testing.T) *db.Store {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestLimiterBansAfterThreshold(t *testing.T) {
	store := newTestStore(t)
	lim := NewLimiter(store, 3, 15*time.Minute)

	const user, ip = "alice", "1.2.3.4"

	if ok, _ := lim.Allowed(user, ip); !ok {
		t.Fatal("başta izin verilmeliydi")
	}
	lim.RecordFailure(user, ip)
	lim.RecordFailure(user, ip)
	if ok, _ := lim.Allowed(user, ip); !ok {
		t.Fatal("2 başarısızlıkta hâlâ izin verilmeliydi")
	}
	lim.RecordFailure(user, ip)
	if ok, _ := lim.Allowed(user, ip); ok {
		t.Fatal("3 başarısızlıktan sonra banlanmalıydı")
	}

	// Başarılı giriş geçmişi temizler.
	lim.RecordSuccess(user, ip)
	if ok, _ := lim.Allowed(user, ip); !ok {
		t.Fatal("başarılı girişten sonra tekrar izin verilmeliydi")
	}
}

func TestLimiterIsolatesByIP(t *testing.T) {
	store := newTestStore(t)
	lim := NewLimiter(store, 2, 15*time.Minute)

	lim.RecordFailure("alice", "1.1.1.1")
	lim.RecordFailure("alice", "1.1.1.1")
	if ok, _ := lim.Allowed("alice", "1.1.1.1"); ok {
		t.Fatal("1.1.1.1 banlanmalıydı")
	}
	if ok, _ := lim.Allowed("alice", "2.2.2.2"); !ok {
		t.Fatal("farklı IP banlanmamalıydı")
	}
}
