// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package proxy, JumpBox'tan hedef sunuculara SSH istemci bağlantısı kurar ve
// kullanıcının terminalini uzak shell'e şeffaf biçimde bağlar.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"jumpbox/internal/crypto"
	"jumpbox/internal/db"
	"jumpbox/internal/model"
)

// WinSource, terminal boyut değişikliklerine abone olunmasını sağlar.
// Callback parametreleri: w = sütun (cols), h = satır (rows).
type WinSource interface {
	Subscribe(func(w, h int))
}

// Proxy, uzak sunuculara bağlanmak için gerekli depo ve şifre çözücüyü tutar.
type Proxy struct {
	store *db.Store
	vault *crypto.Vault
}

// New, yeni bir Proxy oluşturur.
func New(store *db.Store, vault *crypto.Vault) *Proxy {
	return &Proxy{store: store, vault: vault}
}

// ErrNoKey, sunucuya SSH anahtarı atanmadığında döner.
var ErrNoKey = errors.New("sunucuya SSH anahtarı atanmamış")

// Connect, hedef sunucuya bağlanır ve in/out akışlarını uzak interaktif shell'e
// bağlar. Çağrı, uzak oturum kapanana (veya ctx iptal edilene) kadar bloklar.
// Dönüş değeri yalnızca bağlantı/kurulum hatalarında doludur; uzak shell'in
// normal (hatalı çıkış kodu dahil) sonlanması nil döndürür.
func (p *Proxy) Connect(ctx context.Context, in io.Reader, out io.Writer, srv model.Server, term string, cols, rows int, win WinSource) error {
	if srv.SSHKeyID == 0 {
		return ErrNoKey
	}

	signer, err := p.signerForServer(srv)
	if err != nil {
		return err
	}

	cfg := &ssh.ClientConfig{
		User:            srv.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: p.hostKeyCallback(srv.Addr()),
		Timeout:         15 * time.Second,
	}

	dialer := net.Dialer{Timeout: cfg.Timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", srv.Addr())
	if err != nil {
		return fmt.Errorf("bağlantı kurulamadı: %w", err)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(netConn, srv.Addr(), cfg)
	if err != nil {
		netConn.Close()
		return fmt.Errorf("SSH el sıkışması başarısız: %w", err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	// ctx iptal edilirse bağlantıyı kapatarak Wait()'i serbest bırak.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		case <-stop:
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("oturum açılamadı: %w", err)
	}
	defer session.Close()

	session.Stdin = in
	session.Stdout = out
	session.Stderr = out

	if term == "" {
		term = "xterm-256color"
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(term, rows, cols, modes); err != nil {
		return fmt.Errorf("PTY istenemedi: %w", err)
	}

	// Boyut değişikliklerini uzak oturuma ilet.
	if win != nil {
		win.Subscribe(func(w, h int) {
			_ = session.WindowChange(h, w)
		})
		defer win.Subscribe(nil)
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("uzak shell başlatılamadı: %w", err)
	}

	// Uzak oturumun normal sonlanması (çıkış kodu dahil) hata sayılmaz.
	if err := session.Wait(); err != nil {
		var exitErr *ssh.ExitError
		var missing *ssh.ExitMissingError
		if errors.As(err, &exitErr) || errors.As(err, &missing) {
			return nil
		}
		// Bağlantı koptu / kapandı: temiz dönüş.
		return nil
	}
	return nil
}

// signerForServer, sunucuya atanmış şifreli anahtarı çözüp bir ssh.Signer üretir.
func (p *Proxy) signerForServer(srv model.Server) (ssh.Signer, error) {
	key, err := p.store.GetSSHKey(srv.SSHKeyID)
	if err != nil {
		return nil, fmt.Errorf("anahtar bulunamadı: %w", err)
	}
	pemBytes, err := p.vault.Decrypt(key.PrivateKeyEncrypted)
	if err != nil {
		return nil, fmt.Errorf("anahtar çözülemedi: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("özel anahtar ayrıştırılamadı: %w", err)
	}
	return signer, nil
}

// hostKeyCallback, TOFU (ilk görüşte güven) doğrulaması yapar: host anahtarı ilk
// görüldüğünde kaydedilir, sonraki bağlantılarda fingerprint karşılaştırılır.
func (p *Proxy) hostKeyCallback(host string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		stored, err := p.store.GetHostKey(host)
		if errors.Is(err, db.ErrNotFound) {
			return p.store.SetHostKey(host, fp)
		}
		if err != nil {
			return err
		}
		if stored != fp {
			return fmt.Errorf("host anahtarı değişti (olası MITM saldırısı): %s", host)
		}
		return nil
	}
}
