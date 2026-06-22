// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"

	"jumpbox/internal/model"
)

// CreateServer, yeni bir hedef sunucu ekler. Grup üyelikleri ayrıca
// SetServerGroups ile atanır.
func (s *Store) CreateServer(srv model.Server) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO servers(name, hostname, ip, port, username, ssh_key_id) VALUES(?,?,?,?,?,?)`,
		srv.Name, srv.Hostname, srv.IP, srv.Port, srv.Username, nullID(srv.SSHKeyID),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateServer, mevcut bir sunucunun temel alanlarını günceller. Grup üyelikleri
// ayrıca SetServerGroups ile yönetilir.
func (s *Store) UpdateServer(srv model.Server) error {
	_, err := s.db.Exec(
		`UPDATE servers SET name=?, hostname=?, ip=?, port=?, username=?, ssh_key_id=? WHERE id=?`,
		srv.Name, srv.Hostname, srv.IP, srv.Port, srv.Username, nullID(srv.SSHKeyID), srv.ID,
	)
	return err
}

// DeleteServer, bir sunucuyu siler (server_groups satırları ON DELETE CASCADE).
func (s *Store) DeleteServer(id int64) error {
	_, err := s.db.Exec(`DELETE FROM servers WHERE id = ?`, id)
	return err
}

// GetServer, ID'ye göre tek bir sunucuyu getirir.
func (s *Store) GetServer(id int64) (model.Server, error) {
	var srv model.Server
	var keyID sql.NullInt64
	err := s.db.QueryRow(
		`SELECT id, name, hostname, ip, port, username, ssh_key_id, created_at FROM servers WHERE id = ?`, id,
	).Scan(&srv.ID, &srv.Name, &srv.Hostname, &srv.IP, &srv.Port, &srv.Username, &keyID, &srv.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return srv, ErrNotFound
	}
	if err != nil {
		return srv, err
	}
	srv.SSHKeyID = keyID.Int64
	return srv, nil
}

// serverSelectView, sunucuyu anahtar adı ve (virgülle birleşik) grup adlarıyla seçer.
const serverSelectView = `
	SELECT s.id, s.name, s.hostname, s.ip, s.port, s.username, s.ssh_key_id, s.created_at,
	       COALESCE(k.name, ''),
	       COALESCE((SELECT GROUP_CONCAT(g.name, ', ')
	                 FROM server_groups sg JOIN groups g ON g.id = sg.group_id
	                 WHERE sg.server_id = s.id), '')
	FROM servers s
	LEFT JOIN ssh_keys k ON k.id = s.ssh_key_id`

// ListServers, tüm sunucuları listeler (admin görünümü).
func (s *Store) ListServers() ([]model.ServerView, error) {
	rows, err := s.db.Query(serverSelectView + ` ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanServerViews(rows)
}

// ListServersForUser, kullanıcının izinli gruplarıyla en az bir ortak gruba sahip
// sunucuları listeler. Hiçbir gruba ait olmayan sunucular dahil edilmez.
func (s *Store) ListServersForUser(userID int64) ([]model.ServerView, error) {
	rows, err := s.db.Query(serverSelectView+`
		WHERE EXISTS (
			SELECT 1 FROM server_groups sg
			JOIN user_groups ug ON ug.group_id = sg.group_id
			WHERE sg.server_id = s.id AND ug.user_id = ?
		)
		ORDER BY s.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanServerViews(rows)
}

func scanServerViews(rows *sql.Rows) ([]model.ServerView, error) {
	var out []model.ServerView
	for rows.Next() {
		var v model.ServerView
		var keyID sql.NullInt64
		if err := rows.Scan(&v.ID, &v.Name, &v.Hostname, &v.IP, &v.Port, &v.Username,
			&keyID, &v.CreatedAt, &v.KeyName, &v.GroupNames); err != nil {
			return nil, err
		}
		v.SSHKeyID = keyID.Int64
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetServerGroups, bir sunucunun grup üyeliklerini verilen listeyle değiştirir
// (önce hepsini siler, sonra yenilerini ekler).
func (s *Store) SetServerGroups(serverID int64, groupIDs []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM server_groups WHERE server_id = ?`, serverID); err != nil {
		return err
	}
	for _, gid := range groupIDs {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO server_groups(server_id, group_id) VALUES(?,?)`, serverID, gid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}
