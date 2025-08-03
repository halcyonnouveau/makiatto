CREATE TABLE IF NOT EXISTS peers (
    name TEXT NOT NULL PRIMARY KEY,
    ipv4 TEXT NOT NULL DEFAULT '',
    ipv6 TEXT DEFAULT NULL,
    wg_public_key TEXT NOT NULL DEFAULT '',
    wg_address TEXT NOT NULL DEFAULT '',
    latitude REAL NOT NULL DEFAULT 0.0,
    longitude REAL NOT NULL DEFAULT 0.0,
    is_nameserver INTEGER NOT NULL DEFAULT 0,
    fs_port INTEGER NOT NULL DEFAULT 8282
);

CREATE TABLE IF NOT EXISTS cluster_leadership (
    role TEXT NOT NULL PRIMARY KEY,
    node_name TEXT NOT NULL DEFAULT '',
    term INTEGER NOT NULL DEFAULT 0,
    last_heartbeat INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0
);

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

CREATE TABLE IF NOT EXISTS files (
    domain TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    modified_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (domain, path)
);
