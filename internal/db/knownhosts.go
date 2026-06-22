// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"
)

// GetHostKey, bir host için kayıtlı fingerprint'i döndürür. Yoksa ErrNotFound.
func (s *Store) GetHostKey(host string) (string, error) {
	var fp string
	err := s.db.QueryRow(`SELECT fingerprint FROM known_hosts WHERE host = ?`, host).Scan(&fp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return fp, err
}

// SetHostKey, bir host için fingerprint'i ilk görüşte kaydeder (TOFU).
func (s *Store) SetHostKey(host, fingerprint string) error {
	_, err := s.db.Exec(
		`INSERT INTO known_hosts(host, fingerprint) VALUES(?,?)
		 ON CONFLICT(host) DO UPDATE SET fingerprint=excluded.fingerprint`,
		host, fingerprint,
	)
	return err
}
