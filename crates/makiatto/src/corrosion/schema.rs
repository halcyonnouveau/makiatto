use std::{fs, sync::Arc};

use miette::Result;
use tracing::info;

const MIGRATIONS: &[&str] = &[include_str!("../../migrations/001_initial_schema.sql")];

#[derive(Debug, Clone)]
pub struct Peer {
    pub name: Arc<str>,
    pub ipv4: Arc<str>,
    pub ipv6: Option<Arc<str>>,
    pub wg_public_key: Arc<str>,
    pub wg_address: Arc<str>,
    pub latitude: f64,
    pub longitude: f64,
    pub is_nameserver: bool,
}

#[derive(Debug, Clone)]
pub struct Domain {
    pub name: Arc<str>,
}

#[derive(Debug, Clone)]
pub struct DomainAlias {
    pub alias: Arc<str>,
    pub target: Arc<str>,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: Arc<str>,
    pub domain: Arc<str>,
    pub source_domain: Arc<str>,
    pub record_type: Arc<str>,
    pub value: Arc<str>,
    pub ttl: u32,
    pub priority: i32,
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
