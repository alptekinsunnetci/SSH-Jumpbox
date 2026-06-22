-- 0002_groups: grup tabanlı erişim denetimi (RBAC-lite)

CREATE TABLE IF NOT EXISTS groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Kullanıcı ↔ grup erişim izni (çoktan-çoğa).
CREATE TABLE IF NOT EXISTS user_groups (
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- Her sunucu en fazla bir gruba aittir (NULL = gruba atanmamış, yalnızca admin erişir).
ALTER TABLE servers ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;
