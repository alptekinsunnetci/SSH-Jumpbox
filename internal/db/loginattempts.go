// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

import "time"

// RecordAttempt, bir login denemesini (başarılı/başarısız) kaydeder.
func (s *Store) RecordAttempt(username, ip string, success bool) error {
	_, err := s.db.Exec(
		`INSERT INTO login_attempts(username, ip_address, success) VALUES(?,?,?)`,
		nullStr(username), ip, b2i(success),
	)
	return err
}

// CountRecentFailures, verilen zaman noktasından sonra belirli (kullanıcı,IP) için
// başarısız deneme sayısını döndürür.
func (s *Store) CountRecentFailures(username, ip string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(1) FROM login_attempts
		 WHERE ip_address = ? AND (username = ? OR ? = '')
		   AND success = 0 AND attempted_at >= ?`,
		ip, username, username, since.UTC(),
	).Scan(&n)
	return n, err
}

// ClearFailures, başarılı giriş sonrası (kullanıcı,IP) başarısızlık geçmişini temizler.
func (s *Store) ClearFailures(username, ip string) error {
	_, err := s.db.Exec(
		`DELETE FROM login_attempts WHERE ip_address = ? AND username = ? AND success = 0`,
		ip, username,
	)
	return err
}
