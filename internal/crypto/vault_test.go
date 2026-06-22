// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	v, err := NewVault(testKey())
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	plain := []byte("-----BEGIN OPENSSH PRIVATE KEY----- gizli içerik")
	ct, err := v.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("şifreli metin düz metni içeriyor")
	}
	got, err := v.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("çözülen veri eşleşmiyor: %q", got)
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	v, _ := NewVault(testKey())
	ct, _ := v.Encrypt([]byte("veri"))
	ct[len(ct)-1] ^= 0xFF // GCM etiketini boz
	if _, err := v.Decrypt(ct); err == nil {
		t.Fatal("bozulmuş veri çözülmemeliydi")
	}
}

func TestNewVaultRejectsBadKeySize(t *testing.T) {
	if _, err := NewVault(make([]byte, 16)); err == nil {
		t.Fatal("16 baytlık anahtar reddedilmeliydi")
	}
}

func TestGenerateAndLoadMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := GenerateMasterKey(path); err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if err := GenerateMasterKey(path); err == nil {
		t.Fatal("mevcut anahtarın üzerine yazılmamalıydı")
	}
	key, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("anahtar boyutu 32 olmalı, %d", len(key))
	}
	if _, err := NewVault(key); err != nil {
		t.Fatalf("üretilen anahtarla vault oluşmalı: %v", err)
	}
	_ = os.Chmod(path, 0o600)
}
