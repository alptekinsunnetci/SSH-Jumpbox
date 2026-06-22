// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package model, JumpBox'ın alan (domain) veri yapılarını tanımlar.
package model

import "time"

// User, JumpBox'a giriş yapabilen bir kullanıcıyı temsil eder.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   string
	TOTPEnrolled bool   // false ise ilk girişte QR ile kurulum yapılır
	Language     string // i18n tercihi (tr|en)
	IsAdmin      bool
	CreatedAt    time.Time
}

// AllowedIP, bir kullanıcı için izin verilen kaynak IP/CIDR girdisidir.
type AllowedIP struct {
	ID        int64
	UserID    int64
	IPAddress string
}

// SSHKey, hedef sunuculara bağlanmak için kullanılan, rest'te AES-256-GCM ile
// şifrelenmiş bir SSH özel anahtarını temsil eder.
type SSHKey struct {
	ID                  int64
	Name                string
	PrivateKeyEncrypted []byte // nonce(12) || GCM ciphertext
	PublicKey           string // authorized_keys formatı
	CreatedAt           time.Time
}

// Group, sunucuları gruplayıp kullanıcılara grup bazında erişim vermek için kullanılır.
type Group struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

// Server, JumpBox üzerinden bağlanılabilen bir hedef sunucudur.
// Grup üyelikleri ayrı bir ilişki tablosunda (server_groups) tutulur.
type Server struct {
	ID        int64
	Name      string
	Hostname  string
	IP        string
	Port      int
	Username  string
	SSHKeyID  int64 // 0 = anahtar atanmamış
	CreatedAt time.Time
}

// Addr, bağlantı için "ip:port" biçiminde adres döndürür.
func (s Server) Addr() string {
	return s.IP + ":" + itoa(s.Port)
}

// ServerView, listeleme için sunucuyu atanmış anahtar adı ve grup adlarıyla
// (virgülle birleştirilmiş) birleştirir.
type ServerView struct {
	Server
	KeyName    string
	GroupNames string
}

// AuditEntry, tek bir denetim kaydını temsil eder.
type AuditEntry struct {
	ID           int64
	UserID       int64
	Username     string
	Action       string
	TargetServer string
	IPAddress    string
	Detail       string
	Timestamp    time.Time
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
