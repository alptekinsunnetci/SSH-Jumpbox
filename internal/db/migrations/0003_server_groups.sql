-- 0003_server_groups: bir sunucu birden çok gruba ait olabilsin (çoktan-çoğa).
-- Önceki tek-grup atamaları (servers.group_id) yeni tabloya taşınır.
-- servers.group_id sütunu artık kullanılmaz; geriye dönük uyumluluk için bırakılır.

CREATE TABLE IF NOT EXISTS server_groups (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (server_id, group_id)
);

INSERT OR IGNORE INTO server_groups (server_id, group_id)
    SELECT id, group_id FROM servers WHERE group_id IS NOT NULL;
