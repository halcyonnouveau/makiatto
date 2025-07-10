use std::fs;

use miette::Result;
use tracing::{error, info};

use crate::config::Config;

/// Run the embedded Corrosion agent
pub async fn run(config: Config, tripwire: tripwire::Tripwire) -> Result<()> {
    info!("Starting Corrosion agent for node '{}'", config.node.name);

    if let Err(e) = tokio::fs::create_dir_all(&config.node.data_dir).await {
        error!("Failed to create data directory: {}", e);
        return Err(miette::miette!("Failed to create data directory: {}", e));
    }

    let mut cfg = config.corrosion.clone();

    if config.corrosion.db.schema_paths.is_empty() {
        let schema_path = setup_schema_file(&config.node.data_dir)?;
        cfg.db.schema_paths = vec![schema_path];
    }

    let result = corro_agent::agent::start_with_config(cfg, tripwire.clone()).await;

    let (_agent, _bookie) = match result {
        Ok((agent, bookie)) => {
            info!("Corrosion agent started successfully");
            (agent, bookie)
        }
        Err(e) => {
            error!("Failed to start Corrosion agent: {}", e);
            return Err(miette::miette!("Failed to start Corrosion agent: {}", e));
        }
    };

    tripwire.await;

    info!("Corrosion agent stopped");
    Ok(())
}

const MAKIATTO_SCHEMA: &str = r#"
-- Domains table
CREATE TABLE domains (
    id INTEGER NOT NULL PRIMARY KEY,
    name TEXT NOT NULL DEFAULT "",
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX domains_name_unique ON domains (name);

-- DNS records table
CREATE TABLE dns_records (
    id INTEGER NOT NULL PRIMARY KEY,
    domain_id INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT "",
    record_type TEXT NOT NULL DEFAULT "",
    default_value TEXT NOT NULL DEFAULT "",
    ttl INTEGER NOT NULL DEFAULT 300,
    priority INTEGER DEFAULT NULL,
    geo_enabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_dns_records_lookup ON dns_records (domain_id, name, record_type);
CREATE INDEX idx_dns_records_geo ON dns_records (geo_enabled);

-- Peers table (for GeoDNS and WireGuard mesh)
CREATE TABLE peers (
    id INTEGER NOT NULL PRIMARY KEY,
    name TEXT NOT NULL DEFAULT "",
    latitude REAL NOT NULL DEFAULT 0.0,
    longitude REAL NOT NULL DEFAULT 0.0,
    ipv4 TEXT NOT NULL DEFAULT "",
    ipv6 TEXT DEFAULT NULL,
    wg_public_key TEXT NOT NULL DEFAULT "",
    wg_address TEXT NOT NULL DEFAULT "",
    wg_port INTEGER NOT NULL DEFAULT 51880,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_peers_location ON peers (latitude, longitude);
CREATE INDEX idx_peers_wg_key ON peers (wg_public_key);

-- Certificates table
CREATE TABLE certificates (
    id INTEGER NOT NULL PRIMARY KEY,
    domain_id INTEGER NOT NULL DEFAULT 0,
    certificate_pem TEXT NOT NULL DEFAULT "",
    private_key_pem TEXT NOT NULL DEFAULT "",
    expires_at INTEGER NOT NULL DEFAULT 0,
    issuer TEXT NOT NULL DEFAULT "lets_encrypt",
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_certificates_expiration ON certificates (expires_at);

-- File synchronisation table
CREATE TABLE file_synchronisation (
    id INTEGER NOT NULL PRIMARY KEY,
    domain_id INTEGER NOT NULL DEFAULT 0,
    file_path TEXT NOT NULL DEFAULT "",
    file_hash TEXT NOT NULL DEFAULT "",
    file_size INTEGER NOT NULL DEFAULT 0,
    last_modified INTEGER NOT NULL DEFAULT 0,
    synchronisation_status TEXT NOT NULL DEFAULT "pending",
    error_message TEXT DEFAULT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_file_synchronisation_status ON file_synchronisation (synchronisation_status, updated_at);
CREATE INDEX idx_file_synchronisation_domain ON file_synchronisation (domain_id, synchronisation_status);
"#;

/// Set up schema file and return the file path for Corrosion config
fn setup_schema_file(data_dir: &camino::Utf8PathBuf) -> Result<camino::Utf8PathBuf> {
    info!("Setting up makiatto database schema file...");

    let schema_file_path = data_dir.join("makiatto.sql");
    fs::write(&schema_file_path, MAKIATTO_SCHEMA)
        .map_err(|e| miette::miette!("Failed to write schema file: {e}"))?;

    info!("Wrote schema file: {schema_file_path}");
    Ok(schema_file_path)
}
