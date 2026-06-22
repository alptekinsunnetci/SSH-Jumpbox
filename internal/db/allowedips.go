// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

// AddAllowedIP, bir kullanıcıya izinli IP/CIDR ekler (idempotent).
func (s *Store) AddAllowedIP(userID int64, ip string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO allowed_ips(user_id, ip_address) VALUES(?,?)`, userID, ip)
	return err
}

// ListAllowedIPs, bir kullanıcının izinli IP/CIDR listesini döndürür.
func (s *Store) ListAllowedIPs(userID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT ip_address FROM allowed_ips WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// RemoveAllowedIP, bir kullanıcıdan bir IP/CIDR girdisini siler.
func (s *Store) RemoveAllowedIP(userID int64, ip string) error {
	_, err := s.db.Exec(`DELETE FROM allowed_ips WHERE user_id = ? AND ip_address = ?`, userID, ip)
	return err
}
