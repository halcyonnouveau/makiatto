use std::{fs, sync::Arc};

use miette::Result;
use tracing::info;

const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE IF NOT EXISTS peers (
    name TEXT NOT NULL PRIMARY KEY,
    ipv4 TEXT NOT NULL DEFAULT '',
    ipv6 TEXT DEFAULT NULL,
    wg_public_key TEXT NOT NULL DEFAULT '',
    wg_address TEXT NOT NULL DEFAULT '',
    latitude REAL NOT NULL DEFAULT 0.0,
    longitude REAL NOT NULL DEFAULT 0.0,
    created_at TIMESTAMP NOT NULL DEFAULT (datetime('subsecond')),
    updated_at TIMESTAMP NOT NULL DEFAULT (datetime('subsecond'))
);

CREATE TABLE IF NOT EXISTS dns_records (
    domain TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    record_type TEXT NOT NULL DEFAULT '',
    base_value TEXT NOT NULL DEFAULT '',
    ttl INTEGER NOT NULL DEFAULT 300,
    priority INTEGER DEFAULT NULL,
    geo_enabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS certificates (
    domain TEXT NOT NULL PRIMARY KEY,
    certificate_pem TEXT NOT NULL DEFAULT '',
    private_key_pem TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL DEFAULT '',
    issuer TEXT NOT NULL DEFAULT "lets_encrypt"
);

CREATE TABLE IF NOT EXISTS cluster_leadership (
    role TEXT NOT NULL PRIMARY KEY,
    node_name TEXT NOT NULL DEFAULT '',
    term INTEGER NOT NULL DEFAULT 0,
    last_heartbeat INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS certificate_renewals (
    domain TEXT NOT NULL PRIMARY KEY,
    last_check INTEGER NOT NULL DEFAULT 0,
    last_renewal INTEGER DEFAULT NULL,
    renewal_status TEXT NOT NULL DEFAULT 'pending',
    next_check INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS acme_challenges (
    token TEXT NOT NULL PRIMARY KEY,
    key_authorisation TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0
);"#];

#[derive(Debug, Clone)]
pub struct Peer {
    pub name: Arc<str>,
    pub ipv4: Arc<str>,
    pub ipv6: Option<Arc<str>>,
    pub wg_public_key: Arc<str>,
    pub wg_address: Arc<str>,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub record_type: Arc<str>,
    pub base_value: Arc<str>,
    pub ttl: u32,
    pub priority: Option<i32>,
    pub geo_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub domain: Arc<str>,
    pub certificate_pem: Arc<str>,
    pub private_key_pem: Arc<str>,
    pub expires_at: i64,
    pub issuer: Arc<str>,
}

#[derive(Debug, Clone)]
pub struct ClusterLeadership {
    pub role: Arc<str>,
    pub node_name: Arc<str>,
    pub term: i64,
    pub last_heartbeat: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct CertificateRenewal {
    pub domain: Arc<str>,
    pub last_check: i64,
    pub last_renewal: Option<i64>,
    pub renewal_status: Arc<str>,
    pub next_check: i64,
    pub retry_count: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcmeChallenge {
    pub token: Arc<str>,
    pub key_authorisation: Arc<str>,
    pub created_at: i64,
    pub expires_at: i64,
}

pub(crate) fn setup_migrations(data_dir: &camino::Utf8PathBuf) -> Result<Vec<camino::Utf8PathBuf>> {
    info!("Setting up makiatto database migrations...");

    let schema_dir = data_dir.join("schema");
    let mut paths: Vec<camino::Utf8PathBuf> = vec![];

    if !schema_dir.exists() {
        std::fs::create_dir_all(&schema_dir)
            .map_err(|e| miette::miette!("Failed to create schema dir: {e}"))?;
    }

    for (i, el) in MIGRATIONS.iter().enumerate() {
        let path = &schema_dir.join(format!("migration-{i}.sql"));
        fs::write(path, el).map_err(|e| miette::miette!("Failed to write schema file: {e}"))?;
        paths.push(path.to_owned());
    }

    Ok(paths)
}
