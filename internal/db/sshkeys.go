// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"

	"jumpbox/internal/model"
)

// CreateSSHKey, şifrelenmiş bir SSH anahtarını kaydeder ve ID'sini döndürür.
func (s *Store) CreateSSHKey(k model.SSHKey) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO ssh_keys(name, private_key_encrypted, public_key) VALUES(?,?,?)`,
		k.Name, k.PrivateKeyEncrypted, k.PublicKey,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetSSHKey, ID'ye göre şifreli SSH anahtarını getirir.
func (s *Store) GetSSHKey(id int64) (model.SSHKey, error) {
	var k model.SSHKey
	err := s.db.QueryRow(
		`SELECT id, name, private_key_encrypted, public_key, created_at FROM ssh_keys WHERE id = ?`, id,
	).Scan(&k.ID, &k.Name, &k.PrivateKeyEncrypted, &k.PublicKey, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return k, ErrNotFound
	}
	return k, err
}

// ListSSHKeys, tüm anahtarları (özel anahtar hariç) listeler.
func (s *Store) ListSSHKeys() ([]model.SSHKey, error) {
	rows, err := s.db.Query(`SELECT id, name, public_key, created_at FROM ssh_keys ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SSHKey
	for rows.Next() {
		var k model.SSHKey
		if err := rows.Scan(&k.ID, &k.Name, &k.PublicKey, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteSSHKey, bir anahtarı siler. Bu anahtarı kullanan sunucuların ssh_key_id
// alanı NULL olur (migration'daki ON DELETE SET NULL).
func (s *Store) DeleteSSHKey(id int64) error {
	_, err := s.db.Exec(`DELETE FROM ssh_keys WHERE id = ?`, id)
	return err
}

// GetSSHKeyByName, ada göre anahtarı getirir (CLI için).
func (s *Store) GetSSHKeyByName(name string) (model.SSHKey, error) {
	var k model.SSHKey
	err := s.db.QueryRow(
		`SELECT id, name, private_key_encrypted, public_key, created_at FROM ssh_keys WHERE name = ?`, name,
	).Scan(&k.ID, &k.Name, &k.PrivateKeyEncrypted, &k.PublicKey, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return k, ErrNotFound
	}
	return k, err
}
