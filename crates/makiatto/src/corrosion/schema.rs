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
    pub record_type: String,
    pub base_value: String,
    pub ttl: u32,
    pub priority: Option<i32>,
    pub geo_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub domain: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub expires_at: i64,
    pub issuer: String,
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
