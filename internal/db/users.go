// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"

	"jumpbox/internal/model"
)

// ErrNotFound, aranan kaydın bulunamadığını belirtir.
var ErrNotFound = errors.New("kayıt bulunamadı")

// CreateUser, yeni bir kullanıcı ekler ve atanan ID'yi döndürür.
func (s *Store) CreateUser(u model.User) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO users(username, password_hash, totp_secret, totp_enrolled, language, is_admin)
		 VALUES(?,?,?,?,?,?)`,
		u.Username, u.PasswordHash, u.TOTPSecret, b2i(u.TOTPEnrolled), nz(u.Language, "tr"), b2i(u.IsAdmin),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetUserByUsername, kullanıcı adına göre kullanıcıyı getirir.
func (s *Store) GetUserByUsername(username string) (model.User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id, username, password_hash, totp_secret, totp_enrolled, language, is_admin, created_at
		 FROM users WHERE username = ?`, username))
}

// GetUserByID, ID'ye göre kullanıcıyı getirir.
func (s *Store) GetUserByID(id int64) (model.User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id, username, password_hash, totp_secret, totp_enrolled, language, is_admin, created_at
		 FROM users WHERE id = ?`, id))
}

func (s *Store) scanUser(row *sql.Row) (model.User, error) {
	var u model.User
	var enrolled, admin int
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &enrolled, &u.Language, &admin, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	u.TOTPEnrolled = enrolled != 0
	u.IsAdmin = admin != 0
	return u, nil
}

// ListUsers, tüm kullanıcıları (sırlar hariç) listeler.
func (s *Store) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query(
		`SELECT id, username, totp_enrolled, language, is_admin, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		var enrolled, admin int
		if err := rows.Scan(&u.ID, &u.Username, &enrolled, &u.Language, &admin, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.TOTPEnrolled = enrolled != 0
		u.IsAdmin = admin != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUser, bir kullanıcıyı (ve ON DELETE CASCADE ile izinli IP'lerini) siler.
func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// CountUsers, toplam kullanıcı sayısını döndürür (bootstrap kontrolü için).
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&n)
	return n, err
}

// SetTOTPEnrolled, kullanıcının TOTP kurulum durumunu günceller.
func (s *Store) SetTOTPEnrolled(userID int64, enrolled bool) error {
	_, err := s.db.Exec(`UPDATE users SET totp_enrolled = ? WHERE id = ?`, b2i(enrolled), userID)
	return err
}

// SetLanguage, kullanıcının dil tercihini kalıcı olarak günceller.
func (s *Store) SetLanguage(userID int64, lang string) error {
	_, err := s.db.Exec(`UPDATE users SET language = ? WHERE id = ?`, lang, userID)
	return err
}

// SetPassword, kullanıcının parola hash'ini günceller.
func (s *Store) SetPassword(userID int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
