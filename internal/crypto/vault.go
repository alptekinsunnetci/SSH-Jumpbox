// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package crypto, SSH özel anahtarlarını rest'te AES-256-GCM ile şifreler/çözer
// ve filesystem üzerindeki ana anahtarı (master key) güvenli biçimde yükler.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

// masterKeySize, AES-256 için gereken ham anahtar boyutudur (32 bayt).
const masterKeySize = 32

// nonceSize, GCM nonce uzunluğudur.
const nonceSize = 12

// Vault, yüklenmiş bir ana anahtarla şifreleme işlemleri sağlar.
type Vault struct {
	aead cipher.AEAD
}

// NewVault, 32 baytlık bir ana anahtardan bir Vault üretir.
func NewVault(masterKey []byte) (*Vault, error) {
	if len(masterKey) != masterKeySize {
		return nil, fmt.Errorf("ana anahtar %d bayt olmalı, %d bayt verildi", masterKeySize, len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// Encrypt, düz metni şifreler. Çıktı: nonce(12) || ciphertext+tag.
func (v *Vault) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal nonce'u başa ekler (dst = nonce) ve ciphertext'i sona yazar.
	return v.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt, Encrypt ile üretilmiş bir bloğu çözer.
func (v *Vault) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < nonceSize {
		return nil, errors.New("şifreli veri çok kısa")
	}
	nonce, ciphertext := blob[:nonceSize], blob[nonceSize:]
	return v.aead.Open(nil, nonce, ciphertext, nil)
}

// LoadMasterKey, dosyadan 32 baytlık ana anahtarı okur. Linux'ta dosya izinlerinin
// 0600 (grup/diğerlerine kapalı) olduğunu doğrular.
func LoadMasterKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ana anahtar okunamadı: %w", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("ana anahtar dosya izinleri çok açık (%o); 0600 olmalı: %s", perm, path)
		}
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != masterKeySize {
		return nil, fmt.Errorf("ana anahtar %d bayt olmalı, dosyada %d bayt var", masterKeySize, len(key))
	}
	return key, nil
}

// GenerateMasterKey, yeni rastgele bir ana anahtar üretip 0600 izinle yazar.
// Dosya zaten varsa üzerine yazmaz (kazara anahtar kaybını önler).
func GenerateMasterKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("ana anahtar zaten mevcut: %s", path)
	}
	key := make([]byte, masterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	return os.WriteFile(path, key, 0o600)
}
