// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"

	"jumpbox/internal/model"
)

// AddAudit, bir denetim kaydını veritabanına ekler.
func (s *Store) AddAudit(e model.AuditEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_logs(user_id, username, action, target_server, ip_address, detail)
		 VALUES(?,?,?,?,?,?)`,
		nullID(e.UserID), nullStr(e.Username), e.Action, nullStr(e.TargetServer), nullStr(e.IPAddress), nullStr(e.Detail),
	)
	return err
}

// ListAuditByUser, bir kullanıcının en son denetim kayıtlarını döndürür.
func (s *Store) ListAuditByUser(userID int64, limit int) ([]model.AuditEntry, error) {
	rows, err := s.db.Query(`
		SELECT id, COALESCE(user_id,0), COALESCE(username,''), action,
		       COALESCE(target_server,''), COALESCE(ip_address,''), COALESCE(detail,''), timestamp
		FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAudit(rows)
}

// ListAuditAll, tüm kullanıcılar için en son denetim kayıtlarını döndürür (admin).
func (s *Store) ListAuditAll(limit int) ([]model.AuditEntry, error) {
	rows, err := s.db.Query(`
		SELECT id, COALESCE(user_id,0), COALESCE(username,''), action,
		       COALESCE(target_server,''), COALESCE(ip_address,''), COALESCE(detail,''), timestamp
		FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAudit(rows)
}

func scanAudit(rows *sql.Rows) ([]model.AuditEntry, error) {
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action,
			&e.TargetServer, &e.IPAddress, &e.Detail, &e.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
