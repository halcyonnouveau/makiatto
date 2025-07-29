use std::sync::{Arc, OnceLock};

use camino::Utf8Path;
use miette::Result;
use schema::{DnsRecord, Peer};
use sqlx::SqlitePool;
use tracing::{error, info};

use crate::config::Config;
use crate::constants::CORROSION_API_PORT;

pub mod consensus;
pub mod schema;
pub mod subscriptions;

static POOL: OnceLock<SqlitePool> = OnceLock::new();

/// Initialise the `SQLite` connection pool with retry logic
///
/// # Errors
/// Returns an error if the pool cannot be created or is already initialised
pub async fn init_pool(db_path: &Utf8Path) -> Result<()> {
    let database_url = format!("sqlite:{db_path}");

    for attempt in 1..=10 {
        match SqlitePool::connect(&database_url).await {
            Ok(pool) => {
                POOL.set(pool)
                    .map_err(|_| miette::miette!("Connection pool already initialised"))?;

                info!("Initialised SQLite connection pool for: {db_path}");
                return Ok(());
            }
            Err(_) => {
                if attempt < 10 {
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    Err(miette::miette!("Failed to create connection pool"))
}

/// Get a reference to the connection pool with retry logic
///
/// # Errors
/// Returns an error if the pool is not initialised after retries
pub async fn get_pool() -> Result<&'static SqlitePool> {
    for attempt in 1..=10 {
        if let Some(pool) = POOL.get() {
            return Ok(pool);
        }

        if attempt < 10 {
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        }
    }

    Err(miette::miette!(
        "Database not ready yet - Corrosion may still be starting"
    ))
}

/// Get all peers from the database, excluding the current machine
///
/// # Errors
/// Returns an error if the database query fails
pub async fn get_peers() -> Result<Arc<[Peer]>> {
    let pool = get_pool().await?;

    let rows = sqlx::query!(
        "SELECT name, wg_public_key, wg_address, ipv4, ipv6, latitude, longitude, is_nameserver FROM peers"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| miette::miette!("Failed to query peers: {e}"))?;

    let peers: Vec<Peer> = rows
        .into_iter()
        .map(|row| Peer {
            name: Arc::from(row.name),
            ipv4: Arc::from(row.ipv4),
            ipv6: row.ipv6.map(Arc::from),
            wg_public_key: Arc::from(row.wg_public_key),
            wg_address: Arc::from(row.wg_address),
            latitude: row.latitude,
            longitude: row.longitude,
            is_nameserver: row.is_nameserver != 0,
        })
        .collect();

    info!("Retrieved {} peers from database", peers.len());
    Ok(peers.into())
}

/// Get all DNS records from the database
///
/// # Errors
/// Returns an error if the database query fails
pub async fn get_dns_records() -> Result<std::collections::HashMap<String, Vec<DnsRecord>>> {
    let pool = get_pool().await?;

    let rows = sqlx::query!(
        "SELECT domain, name, record_type, value, source_domain, ttl, priority, geo_enabled FROM dns_records"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| miette::miette!("Failed to query DNS records: {e}"))?;

    let mut records_map = std::collections::HashMap::new();
    for row in rows {
        let lookup_key = row.domain.clone();
        let record = DnsRecord {
            name: Arc::from(row.name),
            domain: Arc::from(row.domain),
            source_domain: Arc::from(row.source_domain),
            record_type: Arc::from(row.record_type),
            value: Arc::from(row.value),
            ttl: row.ttl.try_into().unwrap_or(0),
            priority: row.priority.try_into().unwrap_or(0),
            geo_enabled: row.geo_enabled != 0,
        };
        records_map
            .entry(lookup_key)
            .or_insert_with(Vec::new)
            .push(record);
    }

    info!(
        "Retrieved {} DNS record entries from database",
        records_map.len()
    );
    Ok(records_map)
}

/// Get all domains from the database
///
/// # Errors
/// Returns an error if the database query fails
pub async fn get_domains() -> Result<Vec<String>> {
    let pool = get_pool().await?;

    let rows = sqlx::query!("SELECT name FROM domains")
        .fetch_all(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query domains: {e}"))?;

    let domains: Vec<String> = rows.into_iter().map(|row| row.name).collect();

    info!("Retrieved {} domains from database", domains.len());
    Ok(domains)
}

/// Automatically generate nameserver DNS records for all nameserver peers and domains
///
/// This creates A and AAAA records for <peer.name>.ns.<domain> for each nameserver peer
/// and domain combination, allowing automatic NS record generation.
///
/// # Errors
/// Returns an error if database operations fail
pub async fn generate_nameserver_records() -> Result<()> {
    let pool = get_pool().await?;

    // Get all nameserver peers
    let nameserver_peers: Vec<_> = get_peers()
        .await?
        .iter()
        .filter(|peer| peer.is_nameserver)
        .cloned()
        .collect();

    if nameserver_peers.is_empty() {
        info!("No nameserver peers found, skipping nameserver record generation");
        return Ok(());
    }

    // Get all domains
    let domains = get_domains().await?;

    if domains.is_empty() {
        info!("No domains found, skipping nameserver record generation");
        return Ok(());
    }

    info!(
        "Generating nameserver records for {} nameserver peers and {} domains",
        nameserver_peers.len(),
        domains.len()
    );

    // Generate records for each nameserver peer + domain combination
    for peer in &nameserver_peers {
        for domain in &domains {
            let ns_hostname = format!("{}.ns.{}", peer.name, domain);

            // Create A record for IPv4
            let ipv4_value = peer.ipv4.as_ref();
            sqlx::query!(
                "INSERT OR REPLACE INTO dns_records (domain, name, record_type, value, source_domain, ttl, priority, geo_enabled)
                 VALUES (?, ?, 'A', ?, ?, 300, 0, 0)",
                domain,
                ns_hostname,
                ipv4_value,
                domain
            )
            .execute(pool)
            .await
            .map_err(|e| miette::miette!("Failed to insert A record for {}: {e}", ns_hostname))?;

            // Create AAAA record for IPv6 (if available)
            if let Some(ipv6) = &peer.ipv6 {
                let ipv6_value = ipv6.as_ref();
                sqlx::query!(
                    "INSERT OR REPLACE INTO dns_records (domain, name, record_type, value, source_domain, ttl, priority, geo_enabled)
                     VALUES (?, ?, 'AAAA', ?, ?, 300, 0, 0)",
                    domain,
                    ns_hostname,
                    ipv6_value,
                    domain
                )
                .execute(pool)
                .await
                .map_err(|e| miette::miette!("Failed to insert AAAA record for {}: {e}", ns_hostname))?;

                info!(
                    "Generated A and AAAA nameserver records for {}",
                    ns_hostname
                );
            } else {
                info!("Generated A nameserver record for {}", ns_hostname);
            }
        }
    }

    info!(
        "Successfully generated nameserver records for {} nameserver peers",
        nameserver_peers.len()
    );
    Ok(())
}

/// Execute a SQL transaction via Corrosion API
///
/// # Errors
/// Returns an error if the HTTP request fails or the API returns an error
pub async fn execute_transaction(sql: &str) -> Result<()> {
    let json_payload = format!(
        "[\"{}\"]",
        sql.replace('"', "\\\"").replace('\n', " ").trim()
    );

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{CORROSION_API_PORT}/v1/transactions"
        ))
        .header("Content-Type", "application/json")
        .body(json_payload)
        .send()
        .await
        .map_err(|e| miette::miette!("Failed to send transaction: {e}"))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(miette::miette!("Corrosion API error: {error_text}"));
    }

    Ok(())
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

            if let Err(e) = init_pool(&config.corrosion.db.path).await {
                error!("Failed to initialise connection pool after Corrosion startup: {e}");
            } else {
                info!("Connection pool initialised after Corrosion startup");
            }

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
