// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"jumpbox/internal/audit"
	"jumpbox/internal/config"
	"jumpbox/internal/db"
	"jumpbox/internal/i18n"
	"jumpbox/internal/model"
)

// Authenticator, parola + IP + TOTP kimlik doğrulama zincirini yürütür.
type Authenticator struct {
	store   *db.Store
	limiter *Limiter
	audit   *audit.Logger
	cfg     config.Config
}

// NewAuthenticator, yeni bir Authenticator oluşturur.
func NewAuthenticator(store *db.Store, limiter *Limiter, auditor *audit.Logger, cfg config.Config) *Authenticator {
	return &Authenticator{store: store, limiter: limiter, audit: auditor, cfg: cfg}
}

// errAuthFailed, istemciye dönen genel hata (kullanıcı sayımını engellemek için
// tüm başarısızlıklar aynı mesajı verir).
var errAuthFailed = errors.New("kimlik doğrulama başarısız")

// Callback, ssh.ServerConfig.KeyboardInteractiveCallback ile uyumlu imzaya sahiptir.
func (a *Authenticator) Callback(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	username := conn.User()
	ip := HostFromAddr(conn.RemoteAddr().String())
	lang := i18n.Normalize(a.cfg.DefaultLang)

	// 1) Root login tamamen yasak.
	if username == "root" {
		a.audit.Event(0, username, audit.ActionLoginFail, "", ip, "root login reddedildi")
		return nil, errAuthFailed
	}

	// 2) Rate limit / geçici ban kontrolü.
	if ok, err := a.limiter.Allowed(username, ip); err == nil && !ok {
		a.audit.Event(0, username, audit.ActionLoginBan, "", ip, "")
		_, _ = challenge("", i18n.T(lang, "auth.banned"), nil, nil)
		return nil, errAuthFailed
	}

	user, userErr := a.store.GetUserByUsername(username)
	if userErr == nil {
		lang = i18n.Normalize(user.Language)
	}

	// 3) IP whitelist (kullanıcı varsa).
	if userErr == nil {
		allowed, _ := a.store.ListAllowedIPs(user.ID)
		if !CheckIP(ip, allowed) {
			a.limiter.RecordFailure(username, ip)
			a.audit.Event(user.ID, username, audit.ActionIPDenied, "", ip, "")
			_, _ = challenge("", i18n.T(lang, "auth.ip_denied"), nil, nil)
			return nil, errAuthFailed
		}
	}

	// 4) Parola istemi.
	answers, err := challenge(
		i18n.T(lang, "auth.title"),
		i18n.T(lang, "auth.welcome"),
		[]string{i18n.T(lang, "prompt.password")},
		[]bool{false},
	)
	if err != nil || len(answers) != 1 {
		a.failLogin(user, username, ip)
		return nil, errAuthFailed
	}
	passOK := userErr == nil && VerifyPassword(user.PasswordHash, answers[0])

	// 5) TOTP — ilk girişte elle-giriş yönergesi, sonrasında doğrulama.
	var instruction string
	if userErr == nil && passOK && !user.TOTPEnrolled {
		account := fmt.Sprintf("%s (%s)", a.cfg.TOTPIssuer, username)
		instruction = i18n.T(lang, "auth.enroll", account, user.TOTPSecret)
	}

	codeAns, err := challenge("", instruction, []string{i18n.T(lang, "prompt.totp")}, []bool{true})
	if err != nil || len(codeAns) != 1 {
		a.failLogin(user, username, ip)
		return nil, errAuthFailed
	}
	totpOK := userErr == nil && ValidateTOTP(codeAns[0], user.TOTPSecret)

	// Her iki faktör de geçerli olmalı.
	if !passOK || !totpOK {
		a.failLogin(user, username, ip)
		return nil, errAuthFailed
	}

	if !user.TOTPEnrolled {
		_ = a.store.SetTOTPEnrolled(user.ID, true)
	}

	a.limiter.RecordSuccess(username, ip)
	a.audit.Event(user.ID, username, audit.ActionLoginOK, "", ip, "")

	isAdmin := "0"
	if user.IsAdmin {
		isAdmin = "1"
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"user_id":  fmt.Sprintf("%d", user.ID),
			"username": user.Username,
			"lang":     lang,
			"ip":       ip,
			"is_admin": isAdmin,
		},
	}, nil
}

func (a *Authenticator) failLogin(user model.User, username, ip string) {
	a.limiter.RecordFailure(username, ip)
	a.audit.Event(user.ID, username, audit.ActionLoginFail, "", ip, "")
}
