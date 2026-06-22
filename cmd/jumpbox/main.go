// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Command jumpbox, SSH JumpBox (bastion) sunucusunu ve yönetim komutlarını sağlar.
//
// Kullanım:
//
//	jumpbox [-config <yol>] <komut> [argümanlar]
//
// Komutlar:
//
//	serve                         SSH sunucusunu başlat (varsayılan)
//	migrate                       Veritabanı şemasını uygula
//	genkey                        Ana şifreleme anahtarını (master.key) üret
//	useradd [-admin] <kullanıcı>  Kullanıcı oluştur (parola + TOTP)
//	passwd  <kullanıcı>           Kullanıcı parolasını değiştir
//	keygen  <ad>                  Yeni SSH anahtar çifti üret (şifreli sakla)
//	keyimport <ad> <özel-anahtar> Mevcut özel anahtarı içe aktar (şifreli sakla)
//	allow-ip <kullanıcı> <ip|cidr> Kullanıcıya izinli IP/CIDR ekle
//	list-users                    Kullanıcıları listele
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"jumpbox/internal/audit"
	"jumpbox/internal/config"
	"jumpbox/internal/crypto"
	"jumpbox/internal/db"
	"jumpbox/internal/sshserver"
)

func main() {
	configPath := flag.String("config", "/etc/jumpbox/config.yaml", "yapılandırma dosyası yolu")
	addr := flag.String("addr", "", "dinleme adresi override (örn. :2200)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal("yapılandırma yüklenemedi: %v", err)
	}
	if *addr != "" {
		cfg.Addr = *addr
	}

	args := flag.Args()
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}

	switch cmd {
	case "serve":
		cmdServe(cfg)
	case "migrate":
		cmdMigrate(cfg)
	case "genkey":
		cmdGenKey(cfg)
	case "useradd":
		cmdUserAdd(cfg, args)
	case "passwd":
		cmdPasswd(cfg, args)
	case "keygen":
		cmdKeyGen(cfg, args)
	case "keyimport":
		cmdKeyImport(cfg, args)
	case "allow-ip":
		cmdAllowIP(cfg, args)
	case "list-keys":
		cmdListKeys(cfg)
	case "list-users":
		cmdListUsers(cfg)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "bilinmeyen komut: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func cmdServe(cfg config.Config) {
	store := mustOpenStore(cfg)
	defer store.Close()

	masterKey, err := crypto.LoadMasterKey(cfg.MasterKeyPath)
	if err != nil {
		fatal("ana anahtar yüklenemedi (%q): %v\nÖnce 'jumpbox genkey' çalıştırın.", cfg.MasterKeyPath, err)
	}
	vault, err := crypto.NewVault(masterKey)
	if err != nil {
		fatal("vault oluşturulamadı: %v", err)
	}

	mustMkdirParent(cfg.AuditLogPath)
	auditor, err := audit.New(store, cfg.AuditLogPath)
	if err != nil {
		fatal("denetim logu açılamadı: %v", err)
	}
	defer auditor.Close()

	mustMkdirParent(cfg.HostKeyPath)
	srv, err := sshserver.New(cfg, store, vault, auditor)
	if err != nil {
		fatal("sunucu kurulamadı: %v", err)
	}

	if n, _ := store.CountUsers(); n == 0 {
		fmt.Fprintln(os.Stderr, "UYARI: Hiç kullanıcı yok. 'jumpbox useradd -admin <kullanıcı>' ile bir yönetici oluşturun.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("JumpBox dinleniyor: %s\n", cfg.Addr)
	if err := srv.ListenAndServe(ctx); err != nil {
		fatal("sunucu hatası: %v", err)
	}
	fmt.Println("JumpBox kapatıldı.")
}

func cmdMigrate(cfg config.Config) {
	store := mustOpenStore(cfg)
	defer store.Close()
	fmt.Println("Şema güncel.")
}

func cmdGenKey(cfg config.Config) {
	mustMkdirParent(cfg.MasterKeyPath)
	if err := crypto.GenerateMasterKey(cfg.MasterKeyPath); err != nil {
		fatal("ana anahtar üretilemedi: %v", err)
	}
	fmt.Printf("Ana anahtar üretildi: %s (izin 0600)\n", cfg.MasterKeyPath)
}

// mustOpenStore, veritabanını açar ve migration'ları (idempotent) uygular.
func mustOpenStore(cfg config.Config) *db.Store {
	mustMkdirParent(cfg.DBPath)
	store, err := db.Open(cfg.DBPath)
	if err != nil {
		fatal("veritabanı açılamadı (%q): %v", cfg.DBPath, err)
	}
	if err := store.Migrate(); err != nil {
		fatal("migration başarısız: %v", err)
	}
	return store
}

func mustMkdirParent(path string) {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fatal("dizin oluşturulamadı (%q): %v", dir, err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `JumpBox - SSH Bastion

Kullanım: jumpbox [-config <yol>] [-addr <adres>] <komut> [argümanlar]

Komutlar:
  serve                          SSH sunucusunu başlat (varsayılan)
  migrate                        Veritabanı şemasını uygula
  genkey                         Ana şifreleme anahtarını üret
  useradd [-admin] <kullanıcı>   Kullanıcı oluştur (parola + TOTP QR)
  passwd  <kullanıcı>            Parola değiştir
  keygen  <ad>                   Yeni SSH anahtar çifti üret (şifreli)
  keyimport <ad> <özel-anahtar>  Mevcut özel anahtarı içe aktar (şifreli)
  allow-ip <kullanıcı> <ip|cidr> İzinli IP/CIDR ekle
  list-keys                      SSH anahtarlarını (açık anahtar) listele
  list-users                     Kullanıcıları listele
`)
}
