use std::sync::Arc;

use corro_agent::rusqlite::Connection;
use miette::Result;
use tracing::{error, info};

pub mod schema;
pub mod subscriptions;

pub use schema::{DnsRecord, Peer};

use crate::config::Config;

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
            "SELECT name, wg_public_key, wg_address, ipv4, ipv6, latitude, longitude FROM peers;",
        )
        .map_err(|e| miette::miette!("Failed to prepare query: {e}"))?;

    let peer_iter = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let wg_public_key: String = row.get(1)?;
            let wg_address: String = row.get(2)?;
            let ipv4: String = row.get(3)?;
            let ipv6: Option<String> = row.get(4)?;
            let latitude: f64 = row.get(5)?;
            let longitude: f64 = row.get(6)?;

            Ok(Peer {
                name: Arc::from(name),
                ipv4: Arc::from(ipv4),
                ipv6: ipv6.map(Arc::from),
                wg_public_key: Arc::from(wg_public_key),
                wg_address: Arc::from(wg_address),
                latitude,
                longitude,
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

/// Get all DNS records from the database
///
/// # Errors
/// Returns an error if the database query fails
pub fn get_dns_records(
    config: &Config,
) -> Result<std::collections::HashMap<String, Vec<DnsRecord>>> {
    let db_path = &config.corrosion.db.path;

    if !db_path.exists() {
        return Ok(std::collections::HashMap::new());
    }

    let conn =
        Connection::open(db_path).map_err(|e| miette::miette!("Failed to open database: {e}"))?;

    let mut stmt = conn
        .prepare("SELECT domain, name, record_type, value, source_domain, ttl, priority, geo_enabled FROM dns_records")
        .map_err(|e| miette::miette!("Failed to prepare query: {e}"))?;

    let record_iter = stmt
        .query_map([], |row| {
            let domain: String = row.get(0)?;
            let name: String = row.get(1)?;
            let record_type: String = row.get(2)?;
            let value: String = row.get(3)?;
            let source_domain: String = row.get(4)?;
            let ttl: u32 = row.get(5)?;
            let priority: i32 = row.get(6)?;
            let geo_enabled: i32 = row.get(7)?;

            let lookup_key = domain.clone();

            Ok((
                lookup_key,
                DnsRecord {
                    name: Arc::from(name),
                    domain: Arc::from(domain),
                    source_domain: Arc::from(source_domain),
                    record_type: Arc::from(record_type),
                    value: Arc::from(value),
                    ttl,
                    priority,
                    geo_enabled: geo_enabled == 1,
                },
            ))
        })
        .map_err(|e| miette::miette!("Failed to query DNS records: {e}"))?;

    let mut records_map = std::collections::HashMap::new();
    for record_result in record_iter {
        let (key, record) =
            record_result.map_err(|e| miette::miette!("Failed to read DNS record: {e}"))?;
        records_map.entry(key).or_insert_with(Vec::new).push(record);
    }

    info!(
        "Retrieved {} DNS record entries from database",
        records_map.len()
    );
    Ok(records_map)
}

/// Run the embedded Corrosion agent
///
/// # Errors
/// Returns an error if the agent fails to start or encounters runtime errors
pub async fn run(config: Arc<Config>, tripwire: tripwire::Tripwire) -> Result<()> {
    info!("Starting Corrosion agent for node '{}'", config.node.name);

    if let Err(e) = tokio::fs::create_dir_all(&*config.node.data_dir).await {
        error!("Failed to create data directory: {e}");
        return Err(miette::miette!("Failed to create data directory: {}", e));
    }

    let mut cfg = config.corrosion.clone();

    if config.corrosion.db.schema_paths.is_empty() {
        cfg.db.schema_paths = schema::setup_migrations(&config.node.data_dir)?;
    }

    let result = corro_agent::agent::start_with_config(cfg, tripwire.clone()).await;

    let (_agent, _bookie, _transport) = match result {
        Ok((agent, bookie, transport)) => {
            info!("Corrosion agent started successfully");
            (agent, bookie, transport)
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
