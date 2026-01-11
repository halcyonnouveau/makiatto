-- Makiatto database schema
-- Corrosion uses diff-based migrations - just modify this file to add columns/tables
-- See README.md for details

-- Cluster peers
CREATE TABLE IF NOT EXISTS peers (
    name TEXT NOT NULL PRIMARY KEY,
    ipv4 TEXT NOT NULL DEFAULT '',
    ipv6 TEXT DEFAULT NULL,
    wg_public_key TEXT NOT NULL DEFAULT '',
    wg_address TEXT NOT NULL DEFAULT '',
    latitude REAL NOT NULL DEFAULT 0.0,
    longitude REAL NOT NULL DEFAULT 0.0,
    is_nameserver INTEGER NOT NULL DEFAULT 0,
    is_external INTEGER NOT NULL DEFAULT 0,
    fs_port INTEGER NOT NULL DEFAULT 8282
);

-- Leader election
CREATE TABLE IF NOT EXISTS cluster_leadership (
    role TEXT NOT NULL PRIMARY KEY,
    node_name TEXT NOT NULL DEFAULT '',
    term INTEGER NOT NULL DEFAULT 0,
    last_heartbeat INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0
);

-- Health monitoring
CREATE TABLE IF NOT EXISTS unhealthy_nodes (
    node_name TEXT NOT NULL PRIMARY KEY,
    marked_unhealthy_at INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT NOT NULL DEFAULT ''
);

-- Domains and DNS
CREATE TABLE IF NOT EXISTS domains (
    name TEXT NOT NULL PRIMARY KEY DEFAULT ''
);

CREATE TABLE IF NOT EXISTS domain_aliases (
    alias TEXT NOT NULL PRIMARY KEY,
    target TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dns_records (
    id TEXT NOT NULL PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    record_type TEXT NOT NULL DEFAULT '',
    value TEXT NOT NULL DEFAULT '',
    ttl INTEGER NOT NULL DEFAULT 300,
    priority INTEGER NOT NULL DEFAULT 0,
    geo_enabled INTEGER NOT NULL DEFAULT 0
);

-- TLS certificates
CREATE TABLE IF NOT EXISTS certificates (
    domain TEXT NOT NULL PRIMARY KEY,
    certificate_pem TEXT NOT NULL DEFAULT '',
    private_key_pem TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL DEFAULT '',
    issuer TEXT NOT NULL DEFAULT "lets_encrypt"
);

CREATE TABLE IF NOT EXISTS certificate_renewals (
    domain TEXT NOT NULL PRIMARY KEY,
    last_check INTEGER NOT NULL DEFAULT 0,
    renewal_status TEXT NOT NULL DEFAULT 'pending',
    next_check INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_renewal INTEGER DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS acme_challenges (
    token TEXT NOT NULL PRIMARY KEY,
    key_authorisation TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0
);

-- File sync
CREATE TABLE IF NOT EXISTS files (
    domain TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    modified_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (domain, path)
);

-- WASM functions and transforms
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
