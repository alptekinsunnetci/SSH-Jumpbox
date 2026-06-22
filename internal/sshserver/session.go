// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package sshserver

import (
	"context"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/ssh"

	"jumpbox/internal/audit"
	"jumpbox/internal/crypto"
	"jumpbox/internal/db"
	"jumpbox/internal/i18n"
	"jumpbox/internal/model"
	"jumpbox/internal/proxy"
	"jumpbox/internal/tui"
)

type sessionHandler struct {
	store      *db.Store
	audit      *audit.Logger
	proxy      *proxy.Proxy
	vault      *crypto.Vault
	issuer     string
	bcryptCost int
}

// ptyRequest, "pty-req" kanal isteğinin yük (payload) yapısıdır.
type ptyRequest struct {
	Term     string
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

// winChangeRequest, "window-change" kanal isteğinin yük yapısıdır.
type winChangeRequest struct {
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
}

func (h *sessionHandler) handle(ctx context.Context, sshConn *ssh.ServerConn, newChan ssh.NewChannel) {
	// Yalnızca interaktif "session" kanalı; "direct-tcpip" gibi yönlendirme
	// kanalları reddedilir.
	if newChan.ChannelType() != "session" {
		newChan.Reject(ssh.UnknownChannelType, "yalnızca session kanalı desteklenir")
		return
	}
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	ext := sshConn.Permissions.Extensions
	userID, _ := strconv.ParseInt(ext["user_id"], 10, 64)
	username := ext["username"]
	lang := ext["lang"]
	ip := ext["ip"]
	isAdmin := ext["is_admin"] == "1"

	ws := &winState{w: 80, h: 24, term: "xterm-256color"}
	shellReady := make(chan struct{}, 1)

	go func() {
		for req := range reqs {
			switch req.Type {
			case "pty-req":
				var p ptyRequest
				if err := ssh.Unmarshal(req.Payload, &p); err == nil {
					ws.setTerm(p.Term)
					ws.set(int(p.Cols), int(p.Rows))
				}
				req.Reply(true, nil)
			case "window-change":
				var wc winChangeRequest
				if err := ssh.Unmarshal(req.Payload, &wc); err == nil {
					ws.set(int(wc.Cols), int(wc.Rows))
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "shell":
				req.Reply(true, nil)
				select {
				case shellReady <- struct{}{}:
				default:
				}
			case "env":
				req.Reply(true, nil)
			default:
				// exec, subsystem, auth-agent-req@openssh.com vb. reddedilir.
				// (Agent forwarding ve komut bypass'ı engellenir.)
				req.Reply(false, nil)
			}
		}
	}()

	select {
	case <-shellReady:
	case <-ctx.Done():
		return
	}

	h.runInteractive(ctx, ch, ws, userID, username, lang, ip, isAdmin)
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
}

func (h *sessionHandler) runInteractive(ctx context.Context, ch ssh.Channel, ws *winState, userID int64, username, lang, ip string, isAdmin bool) {
	h.audit.Event(userID, username, audit.ActionMenuOpen, "", ip, "")
	deps := tui.Deps{
		Store:      h.store,
		Audit:      h.audit,
		Vault:      h.vault,
		Issuer:     h.issuer,
		BcryptCost: h.bcryptCost,
	}
	curLang := lang
	for {
		w, hgt := ws.get()
		res, newLang := tui.RunMenu(ctx, deps, tui.Session{
			UserID:   userID,
			Username: username,
			Lang:     curLang,
			IP:       ip,
			IsAdmin:  isAdmin,
			Width:    w,
			Height:   hgt,
			Input:    ch,
			Output:   ch,
			Win:      ws,
		})
		curLang = newLang
		if res.Action != tui.ActionConnect {
			return
		}
		h.connect(ctx, ch, ws, userID, username, curLang, ip, isAdmin, res.Server)
		if ctx.Err() != nil {
			return
		}
	}
}

func (h *sessionHandler) connect(ctx context.Context, ch ssh.Channel, ws *winState, userID int64, username, lang, ip string, isAdmin bool, srv model.Server) {
	// Defense-in-depth: TUI listesi zaten filtreli olsa da, erişimi sunucu
	// tarafında bir kez daha doğrula.
	if !isAdmin {
		ok, err := h.store.UserCanAccessServer(userID, srv.ID)
		if err != nil || !ok {
			h.audit.Event(userID, username, audit.ActionAccessDeny, srv.Name, ip, "")
			io.WriteString(ch, "\r\n"+i18n.T(lang, "connect.denied")+"\r\n"+i18n.T(lang, "common.press_enter")+"\r\n")
			waitForKey(ctx, ch)
			return
		}
	}

	h.audit.Event(userID, username, audit.ActionConnect, srv.Name, ip, srv.Addr())
	io.WriteString(ch, "\r\n"+i18n.T(lang, "connect.connecting", srv.Name)+"\r\n")

	w, hgt := ws.get()
	err := h.proxy.Connect(ctx, ch, ch, srv, ws.getTerm(), w, hgt, ws)

	detail := ""
	if err != nil {
		detail = err.Error()
	}
	h.audit.Event(userID, username, audit.ActionSessionEnd, srv.Name, ip, detail)

	// Hata varsa kullanıcı mesajı okuyabilsin diye bir tuşa basana kadar bekle;
	// aksi halde menü hemen yeniden çizilip mesajı siler.
	if err != nil {
		var msg string
		if errors.Is(err, proxy.ErrNoKey) {
			msg = i18n.T(lang, "connect.no_key")
		} else {
			msg = i18n.T(lang, "connect.failed", err.Error())
		}
		io.WriteString(ch, "\r\n"+msg+"\r\n"+i18n.T(lang, "common.press_enter")+"\r\n")
		waitForKey(ctx, ch)
	}
}

// waitForKey, kullanıcıdan tek bir tuş bekler (ctx iptal edilirse hemen döner).
func waitForKey(ctx context.Context, ch ssh.Channel) {
	done := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 1)
		_, _ = ch.Read(buf)
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
