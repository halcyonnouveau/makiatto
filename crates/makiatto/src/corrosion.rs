use std::{fs, sync::Arc};

use corro_agent::rusqlite::Connection;
use miette::Result;
use tracing::{error, info};

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct Peer {
    pub name: String,
    pub wg_public_key: String,
    pub wg_address: String,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub wg_port: i64,
}

/// Run the embedded Corrosion agent
///
/// # Errors
/// Returns an error if the agent fails to start or encounters runtime errors
pub async fn run(config: Config, tripwire: tripwire::Tripwire) -> Result<()> {
    info!("Starting Corrosion agent for node '{}'", config.node.name);

    if let Err(e) = tokio::fs::create_dir_all(&*config.node.data_dir).await {
        error!("Failed to create data directory: {e}");
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
CREATE TABLE IF NOT EXISTS peers (
    name TEXT NOT NULL PRIMARY KEY,
    latitude REAL NOT NULL DEFAULT 0.0,
    longitude REAL NOT NULL DEFAULT 0.0,
    ipv4 TEXT NOT NULL DEFAULT '',
    ipv6 TEXT DEFAULT NULL,
    wg_public_key TEXT NOT NULL DEFAULT '',
    wg_address TEXT NOT NULL DEFAULT '',
    wg_port INTEGER NOT NULL DEFAULT 51880,
    created_at TIMESTAMP NOT NULL DEFAULT (datetime('subsecond')),
    updated_at TIMESTAMP NOT NULL DEFAULT (datetime('subsecond'))
);

CREATE TABLE IF NOT EXISTS dns_records (
    domain TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    record_type TEXT NOT NULL DEFAULT '',
    d_value TEXT NOT NULL DEFAULT '',
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

/// Get all peers from the database, excluding the current machine
///
/// # Errors
/// Returns an error if the database query fails
pub fn get_peers(config: &Config) -> Result<Arc<[Peer]>> {
    let db_path = &config.corrosion.db.path;

    if !db_path.exists() {
        return Err(miette::miette!("Database does not exist"));
    }

    let conn =
        Connection::open(db_path).map_err(|e| miette::miette!("Failed to open database: {e}"))?;

    let mut stmt = conn
        .prepare(
            "SELECT name, wg_public_key, wg_address, ipv4, ipv6, wg_port FROM peers WHERE name != ?1",
        )
        .map_err(|e| miette::miette!("Failed to prepare query: {e}"))?;

    let peer_iter = stmt
        .query_map([&config.node.name], |row| {
            Ok(Peer {
                name: row.get(0)?,
                wg_public_key: row.get(1)?,
                wg_address: row.get(2)?,
                ipv4: row.get(3)?,
                ipv6: row.get(4)?,
                wg_port: row.get(5)?,
            })
        })
        .map_err(|e| miette::miette!("Failed to query peers: {e}"))?;

    let mut peers = Vec::new();
    for peer_result in peer_iter {
        let peer = peer_result.map_err(|e| miette::miette!("Failed to read peer data: {e}"))?;
        peers.push(peer);
    }

    info!("Retrieved {} peers from database", peers.len());
    Ok(peers.into())
}
