-- 0001_init: JumpBox çekirdek şeması (SQLite)

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret   TEXT NOT NULL,
    totp_enrolled INTEGER NOT NULL DEFAULT 0,
    language      TEXT NOT NULL DEFAULT 'tr',
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS allowed_ips (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    UNIQUE(user_id, ip_address)
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT NOT NULL,
    private_key_encrypted BLOB NOT NULL,
    public_key            TEXT NOT NULL,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS servers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    hostname   TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL,
    port       INTEGER NOT NULL DEFAULT 22,
    username   TEXT NOT NULL,
    ssh_key_id INTEGER REFERENCES ssh_keys(id) ON DELETE SET NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER,
    username      TEXT,
    action        TEXT NOT NULL,
    target_server TEXT,
    ip_address    TEXT,
    detail        TEXT,
    timestamp     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT,
    ip_address   TEXT NOT NULL,
    success      INTEGER NOT NULL,
    attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attempts_lookup ON login_attempts(username, ip_address, attempted_at);

-- Uzak sunucu host anahtarları için TOFU (trust-on-first-use) deposu.
CREATE TABLE IF NOT EXISTS known_hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
