// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package db, SQLite tabanlı veri erişim katmanını (Store) sağlar.
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"

	_ "modernc.org/sqlite" // saf Go SQLite sürücüsü (CGO yok)
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store, veritabanı bağlantısını ve repo metodlarını barındırır.
type Store struct {
	db *sql.DB
}

// Open, SQLite veritabanını WAL + foreign_keys + busy_timeout pragmaları ile açar.
func Open(path string) (*Store, error) {
	// modernc sürücüsü pragmaları connection string üzerinden alır.
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)",
		filepath.ToSlash(path),
	)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, err
	}
	return &Store{db: conn}, nil
}

// Close, veritabanı bağlantısını kapatır.
func (s *Store) Close() error { return s.db.Close() }

// Migrate, gömülü migration dosyalarını sırayla, idempotent biçimde uygular.
func (s *Store) Migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return err
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists int
		if err := s.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE name = ?`, name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		sqlBytes, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(sqlBytes)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s başarısız: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(name) VALUES(?)`, name); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
