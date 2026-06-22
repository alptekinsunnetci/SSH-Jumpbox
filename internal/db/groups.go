// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"
	"strings"

	"jumpbox/internal/model"
)

// CreateGroup, yeni bir grup oluşturur.
func (s *Store) CreateGroup(name string) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, errors.New("grup adı boş olamaz")
	}
	res, err := s.db.Exec(`INSERT INTO groups(name) VALUES(?)`, name)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListGroups, tüm grupları döndürür.
func (s *Store) ListGroups() ([]model.Group, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Group
	for rows.Next() {
		var g model.Group
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetGroupByName, ada göre grubu getirir.
func (s *Store) GetGroupByName(name string) (model.Group, error) {
	var g model.Group
	err := s.db.QueryRow(`SELECT id, name, created_at FROM groups WHERE name = ?`, name).
		Scan(&g.ID, &g.Name, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return g, ErrNotFound
	}
	return g, err
}

// DeleteGroup, bir grubu siler. Bu gruptaki sunucuların group_id'si NULL olur,
// kullanıcı-grup izinleri (user_groups) ON DELETE CASCADE ile silinir.
func (s *Store) DeleteGroup(id int64) error {
	_, err := s.db.Exec(`DELETE FROM groups WHERE id = ?`, id)
	return err
}

// AddUserGroup, bir kullanıcıya bir grup erişimi verir (idempotent).
func (s *Store) AddUserGroup(userID, groupID int64) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO user_groups(user_id, group_id) VALUES(?,?)`, userID, groupID)
	return err
}

// RemoveUserGroup, bir kullanıcıdan bir grup erişimini kaldırır.
func (s *Store) RemoveUserGroup(userID, groupID int64) error {
	_, err := s.db.Exec(
		`DELETE FROM user_groups WHERE user_id = ? AND group_id = ?`, userID, groupID)
	return err
}

// ListUserGroupIDs, bir kullanıcının erişebildiği grup ID'lerini küme olarak döndürür.
func (s *Store) ListUserGroupIDs(userID int64) (map[int64]bool, error) {
	rows, err := s.db.Query(`SELECT group_id FROM user_groups WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// UserCanAccessServer, admin olmayan bir kullanıcının belirli bir sunucuya
// erişebilip erişemeyeceğini döndürür. Erişim için sunucu ile kullanıcının en az
// bir ortak grubu olmalıdır.
func (s *Store) UserCanAccessServer(userID, serverID int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(1)
		FROM server_groups sg
		JOIN user_groups ug ON ug.group_id = sg.group_id
		WHERE sg.server_id = ? AND ug.user_id = ?`, serverID, userID).Scan(&n)
	return n > 0, err
}

// ListServerGroupNames, bir sunucunun ait olduğu grup adlarını döndürür.
func (s *Store) ListServerGroupNames(serverID int64) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT g.name FROM server_groups sg
		JOIN groups g ON g.id = sg.group_id
		WHERE sg.server_id = ? ORDER BY g.name`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
