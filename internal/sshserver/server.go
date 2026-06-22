// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package sshserver, JumpBox'ın SSH sunucusunu (golang.org/x/crypto/ssh) ve
// oturum yaşam döngüsünü yönetir.
package sshserver

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"

	"jumpbox/internal/audit"
	"jumpbox/internal/auth"
	"jumpbox/internal/config"
	"jumpbox/internal/crypto"
	"jumpbox/internal/db"
	"jumpbox/internal/proxy"
)

// Server, gelen SSH bağlantılarını kabul eden JumpBox sunucusudur.
type Server struct {
	cfg    config.Config
	store  *db.Store
	audit  *audit.Logger
	vault  *crypto.Vault
	sshCfg *ssh.ServerConfig
	proxy  *proxy.Proxy
}

// New, kimlik doğrulama, host anahtarı ve proxy bileşenlerini kurarak bir Server
// oluşturur.
func New(cfg config.Config, store *db.Store, vault *crypto.Vault, auditor *audit.Logger) (*Server, error) {
	limiter := auth.NewLimiter(store, cfg.Ban.Threshold, cfg.Ban.Window.Std())
	authn := auth.NewAuthenticator(store, limiter, auditor, cfg)

	hostKey, err := LoadOrCreateHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("host anahtarı: %w", err)
	}

	sshCfg := &ssh.ServerConfig{
		// Yalnızca keyboard-interactive: parola + IP + TOTP zinciri burada işler.
		// PublicKey/Password callback'leri TANIMLANMAZ → istemci yerel anahtar
		// veya tek faktörlü parola ile geçemez.
		KeyboardInteractiveCallback: authn.Callback,
		MaxAuthTries:                3,
		ServerVersion:               "SSH-2.0-JumpBox",
	}
	sshCfg.AddHostKey(hostKey)

	return &Server{
		cfg:    cfg,
		store:  store,
		audit:  auditor,
		vault:  vault,
		sshCfg: sshCfg,
		proxy:  proxy.New(store, vault),
	}, nil
}

// ListenAndServe, yapılandırılmış adreste dinler ve ctx iptal edilene kadar
// bağlantıları kabul eder.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve, verilen dinleyici üzerinde bağlantıları kabul eder (test edilebilirlik
// için ayrı tutulmuştur).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, nConn net.Conn) {
	defer nConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshCfg)
	if err != nil {
		// Kimlik doğrulama/el sıkışma başarısız (audit zaten yazıldı).
		return
	}
	defer sshConn.Close()
	if sshConn.Permissions == nil {
		return
	}

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		sshConn.Wait()
		cancel()
	}()

	// Global istekleri yok say (keepalive vb.). Port yönlendirme istekleri burada
	// kabul edilmez.
	go ssh.DiscardRequests(reqs)

	h := &sessionHandler{
		store:      s.store,
		audit:      s.audit,
		proxy:      s.proxy,
		vault:      s.vault,
		issuer:     s.cfg.TOTPIssuer,
		bcryptCost: s.cfg.BcryptCost,
	}
	for newChan := range chans {
		go h.handle(connCtx, sshConn, newChan)
	}
}
