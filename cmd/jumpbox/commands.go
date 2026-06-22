// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"jumpbox/internal/auth"
	"jumpbox/internal/config"
	"jumpbox/internal/crypto"
	"jumpbox/internal/keysvc"
	"jumpbox/internal/model"
)

func cmdUserAdd(cfg config.Config, args []string) {
	admin := false
	var username string
	for _, a := range args {
		switch {
		case a == "-admin" || a == "--admin":
			admin = true
		case strings.HasPrefix(a, "-"):
			fatal("bilinmeyen seçenek: %s", a)
		default:
			username = a
		}
	}
	if username == "" {
		fatal("kullanım: jumpbox useradd [-admin] <kullanıcı>")
	}

	store := mustOpenStore(cfg)
	defer store.Close()

	if _, err := store.GetUserByUsername(username); err == nil {
		fatal("kullanıcı zaten var: %s", username)
	}

	password := readPasswordTwice()
	hash, err := auth.HashPassword(password, cfg.BcryptCost)
	if err != nil {
		fatal("parola hashlenemedi: %v", err)
	}

	key, err := auth.GenerateTOTPSecret(cfg.TOTPIssuer, username)
	if err != nil {
		fatal("TOTP gizli anahtarı üretilemedi: %v", err)
	}

	id, err := store.CreateUser(model.User{
		Username:     username,
		PasswordHash: hash,
		TOTPSecret:   key.Secret(),
		TOTPEnrolled: false,
		Language:     cfg.DefaultLang,
		IsAdmin:      admin,
	})
	if err != nil {
		fatal("kullanıcı oluşturulamadı: %v", err)
	}

	fmt.Printf("\nKullanıcı oluşturuldu: %s (id=%d, admin=%v)\n", username, id, admin)
	fmt.Println("\n=== İki adımlı doğrulama (TOTP) kurulumu ===")
	fmt.Println("Google Authenticator / Authy uygulamasında:")
	fmt.Println("  + (Ekle) → \"Kurulum anahtarı gir\" (Enter a setup key)")
	fmt.Printf("  Hesap adı : %s (%s)\n", cfg.TOTPIssuer, username)
	fmt.Printf("  Anahtar   : %s\n", key.Secret())
	fmt.Println("  Tür       : Zaman tabanlı (Time-based)")
	fmt.Println("\nNOT: Kullanıcı ilk girişte de bu anahtarı ekrandan görecektir.")
}

func cmdPasswd(cfg config.Config, args []string) {
	if len(args) < 1 {
		fatal("kullanım: jumpbox passwd <kullanıcı>")
	}
	store := mustOpenStore(cfg)
	defer store.Close()

	user, err := store.GetUserByUsername(args[0])
	if err != nil {
		fatal("kullanıcı bulunamadı: %s", args[0])
	}
	password := readPasswordTwice()
	hash, err := auth.HashPassword(password, cfg.BcryptCost)
	if err != nil {
		fatal("parola hashlenemedi: %v", err)
	}
	if err := store.SetPassword(user.ID, hash); err != nil {
		fatal("parola güncellenemedi: %v", err)
	}
	fmt.Println("Parola güncellendi.")
}

func cmdKeyGen(cfg config.Config, args []string) {
	if len(args) < 1 {
		fatal("kullanım: jumpbox keygen <ad>")
	}
	name := args[0]
	store := mustOpenStore(cfg)
	defer store.Close()
	vault := mustVault(cfg)

	pubLine, err := keysvc.Generate(store, vault, name)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("SSH anahtarı oluşturuldu: %s\n\nHedef sunucuların authorized_keys dosyasına ekleyin:\n%s\n", name, pubLine)
}

func cmdKeyImport(cfg config.Config, args []string) {
	if len(args) < 2 {
		fatal("kullanım: jumpbox keyimport <ad> <özel-anahtar-dosyası>")
	}
	name, path := args[0], args[1]
	store := mustOpenStore(cfg)
	defer store.Close()
	vault := mustVault(cfg)

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		fatal("özel anahtar okunamadı: %v", err)
	}
	pubLine, err := keysvc.Import(store, vault, name, pemBytes)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("SSH anahtarı içe aktarıldı: %s\n\nAçık anahtar:\n%s\n", name, pubLine)
}

func cmdAllowIP(cfg config.Config, args []string) {
	if len(args) < 2 {
		fatal("kullanım: jumpbox allow-ip <kullanıcı> <ip|cidr>")
	}
	store := mustOpenStore(cfg)
	defer store.Close()

	user, err := store.GetUserByUsername(args[0])
	if err != nil {
		fatal("kullanıcı bulunamadı: %s", args[0])
	}
	if err := store.AddAllowedIP(user.ID, args[1]); err != nil {
		fatal("IP eklenemedi: %v", err)
	}
	fmt.Printf("İzinli IP eklendi: %s -> %s\n", args[0], args[1])
}

func cmdListKeys(cfg config.Config) {
	store := mustOpenStore(cfg)
	defer store.Close()
	keys, err := store.ListSSHKeys()
	if err != nil {
		fatal("anahtarlar listelenemedi: %v", err)
	}
	if len(keys) == 0 {
		fmt.Println("Kayıtlı SSH anahtarı yok. 'jumpbox keygen <ad>' ile oluşturun.")
		return
	}
	fmt.Println("Aşağıdaki AÇIK anahtarları, ilgili hedef sunucuların authorized_keys dosyasına ekleyin:")
	for _, k := range keys {
		fmt.Printf("\n• %s\n  %s\n", k.Name, k.PublicKey)
	}
}

func cmdListUsers(cfg config.Config) {
	store := mustOpenStore(cfg)
	defer store.Close()
	// Basit listeleme: kullanıcı sayısı + ayrıntı için doğrudan sorgu yok;
	// pratikte küçük kurulumlar için yeterli.
	n, _ := store.CountUsers()
	fmt.Printf("Toplam kullanıcı: %d\n", n)
}

// ---- yardımcılar ----

func mustVault(cfg config.Config) *crypto.Vault {
	masterKey, err := crypto.LoadMasterKey(cfg.MasterKeyPath)
	if err != nil {
		fatal("ana anahtar yüklenemedi: %v\nÖnce 'jumpbox genkey' çalıştırın.", err)
	}
	vault, err := crypto.NewVault(masterKey)
	if err != nil {
		fatal("vault oluşturulamadı: %v", err)
	}
	return vault
}

// readPasswordTwice, yeni bir parolayı güvenli biçimde okur. stdin bir terminalse
// echo'suz iki kez sorar ve eşleştiğini doğrular; terminal değilse (otomasyon/test)
// stdin'den tek bir satır okur.
func readPasswordTwice() string {
	fd := int(os.Stdin.Fd())
	var pw string
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Parola: ")
		p1, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal("parola okunamadı: %v", err)
		}
		fmt.Fprint(os.Stderr, "Parola (tekrar): ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal("parola okunamadı: %v", err)
		}
		if string(p1) != string(p2) {
			fatal("parolalar eşleşmiyor")
		}
		pw = string(p1)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			fatal("parola okunamadı: %v", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if len(pw) < 8 {
		fatal("parola en az 8 karakter olmalı")
	}
	return pw
}
