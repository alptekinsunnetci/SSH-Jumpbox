// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package sshserver

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh"

	"jumpbox/internal/audit"
	"jumpbox/internal/auth"
	"jumpbox/internal/config"
	"jumpbox/internal/crypto"
	"jumpbox/internal/db"
	"jumpbox/internal/model"
)

// setupServer, geçici bir admin kullanıcılı JumpBox sunucusu başlatır.
func setupServer(t *testing.T) (addr string, secret string) {
	return setupServerOpt(t, true)
}

// setupServerOpt, verilen yetki düzeyinde bir kullanıcıyla sunucu başlatır ve
// dinlenen adresi döndürür.
func setupServerOpt(t *testing.T, isAdmin bool) (addr string, secret string) {
	t.Helper()
	dir := t.TempDir()

	store, err := db.Open(filepath.Join(dir, "jb.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	key := make([]byte, 32)
	vault, err := crypto.NewVault(key)
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}

	auditor, err := audit.New(store, filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { auditor.Close() })

	// Kullanıcı: bilinen parola + TOTP, enrolled.
	hash, _ := auth.HashPassword("SuperSecret1", 4)
	tkey, _ := auth.GenerateTOTPSecret("JumpBox", "alice")
	secret = tkey.Secret()
	if _, err := store.CreateUser(model.User{
		Username:     "alice",
		PasswordHash: hash,
		TOTPSecret:   secret,
		TOTPEnrolled: true,
		Language:     "tr",
		IsAdmin:      isAdmin,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cfg := config.Default()
	cfg.HostKeyPath = filepath.Join(dir, "host_ed25519")
	cfg.BcryptCost = 4
	cfg.Addr = "127.0.0.1:0"

	srv, err := New(cfg, store, vault, auditor)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)

	return ln.Addr().String(), secret
}

func clientConfig(answerPassword, answerCode string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: "alice",
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					if i < len(echos) && !echos[i] {
						answers[i] = answerPassword // parola (echo kapalı)
					} else {
						answers[i] = answerCode // TOTP kodu (echo açık)
					}
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
}

func TestLoginSuccessAndMenu(t *testing.T) {
	addr, secret := setupServer(t)
	code, _ := totp.GenerateCode(secret, time.Now())

	client, err := ssh.Dial("tcp", addr, clientConfig("SuperSecret1", code))
	if err != nil {
		t.Fatalf("doğru kimlik bilgileriyle giriş başarısız: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	// Menünün başlığını içeren çıktıyı bekle.
	got := readUntil(t, stdout, "JumpBox", 5*time.Second)
	if !strings.Contains(got, "JumpBox") {
		t.Fatalf("menü çıktısı beklenen başlığı içermiyor; alınan: %q", got)
	}

	// 'q' ile menüden çık → oturum sonlanmalı.
	stdin.Write([]byte("q"))
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("oturum 'q' ile zamanında kapanmadı")
	}
}

func TestLoginWrongCodeRejected(t *testing.T) {
	addr, _ := setupServer(t)
	client, err := ssh.Dial("tcp", addr, clientConfig("SuperSecret1", "000000"))
	if err == nil {
		client.Close()
		t.Fatal("yanlış TOTP kodu ile giriş kabul edilmemeliydi")
	}
}

func TestLoginWrongPasswordRejected(t *testing.T) {
	addr, secret := setupServer(t)
	code, _ := totp.GenerateCode(secret, time.Now())
	client, err := ssh.Dial("tcp", addr, clientConfig("yanlis-parola", code))
	if err == nil {
		client.Close()
		t.Fatal("yanlış parola ile giriş kabul edilmemeliydi")
	}
}

func TestRootLoginRejected(t *testing.T) {
	addr, secret := setupServer(t)
	code, _ := totp.GenerateCode(secret, time.Now())
	cfg := clientConfig("SuperSecret1", code)
	cfg.User = "root"
	client, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		client.Close()
		t.Fatal("root girişi reddedilmeliydi")
	}
}

// openMenuOutput, başarılı girişten sonra ilk menü çerçevesini okuyup döndürür.
func openMenuOutput(t *testing.T, addr, secret string) string {
	t.Helper()
	code, _ := totp.GenerateCode(secret, time.Now())
	client, err := ssh.Dial("tcp", addr, clientConfig("SuperSecret1", code))
	if err != nil {
		t.Fatalf("giriş başarısız: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	stdout, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	return readUntil(t, stdout, "JumpBox", 5*time.Second)
}

func TestAdminMenuShowsManagement(t *testing.T) {
	addr, secret := setupServerOpt(t, true)
	out := openMenuOutput(t, addr, secret)
	if !strings.Contains(out, "Kullanıcılar") {
		t.Fatalf("admin menüsünde 'Kullanıcılar' bekleniyordu; alınan: %q", out)
	}
	if !strings.Contains(out, "SSH Anahtarları") {
		t.Fatalf("admin menüsünde 'SSH Anahtarları' bekleniyordu; alınan: %q", out)
	}
}

func TestNonAdminMenuHidesManagement(t *testing.T) {
	addr, secret := setupServerOpt(t, false)
	out := openMenuOutput(t, addr, secret)
	if strings.Contains(out, "Kullanıcılar") {
		t.Fatalf("admin olmayan menüde 'Kullanıcılar' GÖRÜNMEMELİYDİ; alınan: %q", out)
	}
}

// readUntil, hedef alt dize görülene kadar (veya zaman aşımına dek) okur.
func readUntil(t *testing.T, r interface{ Read([]byte) (int, error) }, target string, timeout time.Duration) string {
	t.Helper()
	type res struct {
		data []byte
		err  error
	}
	var sb strings.Builder
	deadline := time.After(timeout)
	ch := make(chan res, 1)
	for {
		go func() {
			buf := make([]byte, 4096)
			n, err := r.Read(buf)
			ch <- res{append([]byte(nil), buf[:n]...), err}
		}()
		select {
		case <-deadline:
			return sb.String()
		case rr := <-ch:
			if len(rr.data) > 0 {
				sb.Write(rr.data)
				if strings.Contains(sb.String(), target) {
					return sb.String()
				}
			}
			if rr.err != nil {
				return sb.String()
			}
		}
	}
}
