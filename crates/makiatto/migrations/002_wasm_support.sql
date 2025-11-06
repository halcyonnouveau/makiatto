CREATE TABLE IF NOT EXISTS domain_functions (
    id TEXT NOT NULL PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    methods TEXT DEFAULT NULL,
    env TEXT NOT NULL DEFAULT '{}',
    timeout_ms INTEGER DEFAULT NULL,
    max_memory_mb INTEGER DEFAULT NULL,
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS domain_transforms (
    id TEXT NOT NULL PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    files_pattern TEXT NOT NULL DEFAULT '',
    env TEXT NOT NULL DEFAULT '{}',
    timeout_ms INTEGER DEFAULT NULL,
    max_memory_mb INTEGER DEFAULT NULL,
    max_file_size_kb INTEGER DEFAULT NULL,
    execution_order INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);
