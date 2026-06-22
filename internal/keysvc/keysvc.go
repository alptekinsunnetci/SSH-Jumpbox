// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package keysvc, SSH anahtarı üretme/içe aktarma işlemlerini (şifreleyip
// veritabanına kaydederek) hem CLI hem TUI için tek noktada toplar.
package keysvc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"jumpbox/internal/crypto"
	"jumpbox/internal/db"
	"jumpbox/internal/model"
)

// Generate, yeni bir ed25519 anahtar çifti üretir, özel anahtarı AES-256-GCM ile
// şifreleyip kaydeder ve eklenecek AÇIK anahtar satırını döndürür.
func Generate(store *db.Store, vault *crypto.Vault, name string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, name)
	if err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if err := save(store, vault, name, pem.EncodeToMemory(block), pubLine); err != nil {
		return "", err
	}
	return pubLine, nil
}

// Import, mevcut (parolasız) bir özel anahtarı içe aktarır.
func Import(store *db.Store, vault *crypto.Vault, name string, pemBytes []byte) (string, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return "", fmt.Errorf("özel anahtar ayrıştırılamadı (parolasız olmalı): %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := save(store, vault, name, pemBytes, pubLine); err != nil {
		return "", err
	}
	return pubLine, nil
}

func save(store *db.Store, vault *crypto.Vault, name string, pemBytes []byte, pubLine string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("anahtar adı boş olamaz")
	}
	if _, err := store.GetSSHKeyByName(name); err == nil {
		return fmt.Errorf("bu adda bir anahtar zaten var: %s", name)
	} else if !errors.Is(err, db.ErrNotFound) {
		return err
	}
	enc, err := vault.Encrypt(pemBytes)
	if err != nil {
		return err
	}
	_, err = store.CreateSSHKey(model.SSHKey{
		Name:                name,
		PrivateKeyEncrypted: enc,
		PublicKey:           pubLine,
	})
	return err
}
