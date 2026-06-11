use std::sync::{Arc, OnceLock};

use camino::Utf8Path;
use miette::Result;
use schema::{DnsRecord, Peer};
use serde::Serialize;
use serde_json::Value;
use sqlx::SqlitePool;
use tracing::{error, info};
use tripwire;

use crate::config::Config;
use crate::r#const::CORROSION_API_PORT;

pub mod consensus;
pub mod health;
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
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }

    Err(miette::miette!(
        "Database not ready yet - Corrosion may still be starting"
    ))
}

/// Get all peers from the database (including the current machine).
///
/// # Errors
/// Returns an error if the database query fails
pub async fn get_peers() -> Result<Arc<[Peer]>> {
    let pool = get_pool().await?;

    let rows = sqlx::query!(
        "SELECT name, wg_public_key, wg_address, ipv4, ipv6, latitude, longitude, is_nameserver, is_external, fs_port FROM peers"
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
            is_external: row.is_external != 0,
            fs_port: row.fs_port,
        })
        .collect();

    Ok(peers.into())
}

/// Get set of unhealthy node names
///
/// # Errors
/// Returns an error if the database query fails
pub async fn get_unhealthy_nodes() -> Result<std::collections::HashSet<String>> {
    let pool = get_pool().await?;

    let rows = sqlx::query!("SELECT node_name FROM unhealthy_nodes")
        .fetch_all(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query unhealthy nodes: {e}"))?;

    let unhealthy_nodes: std::collections::HashSet<String> =
        rows.into_iter().map(|row| row.node_name).collect();

    Ok(unhealthy_nodes)
}

/// Get all DNS records from the database
///
/// # Errors
/// Returns an error if the database query fails
pub async fn get_dns_records() -> Result<std::collections::HashMap<String, Vec<DnsRecord>>> {
    let pool = get_pool().await?;

    let rows = sqlx::query!(
        "SELECT domain, name, record_type, value, ttl, priority, geo_enabled FROM dns_records"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| miette::miette!("Failed to query DNS records: {e}"))?;

    let mut records_map = std::collections::HashMap::new();

    for row in rows {
        let lookup_key = if row.name == "@" {
            row.domain.clone()
        } else {
            format!("{}.{}", row.name.clone(), row.domain.clone())
        };

        let record = DnsRecord {
            domain: Arc::from(row.domain),
            name: Arc::from(row.name),
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

    Ok(domains)
}

/// A SQL statement for the Corrosion `/v1/transactions` API.
///
/// Serialises to Corrosion's wire format: a bare string for [`Statement::Simple`],
/// or `[sql, [params]]` for [`Statement::WithParams`]. Always prefer the
/// parameterised form for any value that is not a compile-time constant — the
/// statement is gossiped to and executed on every node in the cluster, so an
/// unescaped quote is a cluster-wide SQL injection.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Statement {
    /// A literal SQL statement with no bound parameters.
    Simple(String),
    /// A parameterised statement: `(sql, params)` bound positionally to `?`.
    WithParams(String, Vec<Value>),
}

impl Statement {
    /// Build a parameterised statement.
    #[must_use]
    pub fn with_params(sql: impl Into<String>, params: Vec<Value>) -> Self {
        Self::WithParams(sql.into(), params)
    }
}

impl From<String> for Statement {
    fn from(sql: String) -> Self {
        Self::Simple(sql)
    }
}

impl From<&str> for Statement {
    fn from(sql: &str) -> Self {
        Self::Simple(sql.to_string())
    }
}

/// Execute SQL transactions via Corrosion API
///
/// # Errors
/// Returns an error if the HTTP request fails or the API returns an error
pub async fn execute_transactions(statements: &[Statement]) -> Result<()> {
    if statements.is_empty() {
        return Ok(());
    }

    let json_payload = serde_json::to_string(statements)
        .map_err(|e| miette::miette!("Failed to serialise SQL statements: {e}"))?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{CORROSION_API_PORT}/v1/transactions"
        ))
        .header("Content-Type", "application/json")
        .body(json_payload)
        .send()
        .await
        .map_err(|e| miette::miette!("Failed to send transactions: {e}"))?;

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
        cfg.db.schema_paths = schema::setup_paths(&config.node.data_dir)?;
    }

    let result = corro_agent::agent::start_with_config(cfg, tripwire.clone()).await;

    let (_agent, _bookie, _transport, _handles) = match result {
        Ok((agent, bookie, transport, handles)) => {
            info!("Corrosion agent started successfully");

            if let Err(e) = init_pool(&config.corrosion.db.path).await {
                error!("Failed to initialise connection pool after Corrosion startup: {e}");
            } else {
                info!("Connection pool initialised after Corrosion startup");
            }

            (agent, bookie, transport, handles)
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::Statement;

    #[test]
    fn simple_statement_serialises_as_bare_string() {
        let stmt = Statement::from("DELETE FROM files");
        assert_eq!(
            serde_json::to_string(&stmt).unwrap(),
            r#""DELETE FROM files""#
        );
    }

    #[test]
    fn parameterised_statement_serialises_as_sql_and_params() {
        let stmt = Statement::with_params(
            "DELETE FROM files WHERE domain = ? AND path = ?",
            vec![json!("a'; DROP TABLE files;--"), json!("/index.html")],
        );
        // the dangerous value stays in the params array, never interpolated into SQL
        assert_eq!(
            serde_json::to_string(&stmt).unwrap(),
            r#"["DELETE FROM files WHERE domain = ? AND path = ?",["a'; DROP TABLE files;--","/index.html"]]"#
        );
    }

    #[test]
    fn transaction_batch_serialises_as_array() {
        let stmts = vec![
            Statement::from("BEGIN"),
            Statement::with_params("INSERT INTO t VALUES (?)", vec![json!(1)]),
        ];
        assert_eq!(
            serde_json::to_string(&stmts).unwrap(),
            r#"["BEGIN",["INSERT INTO t VALUES (?)",[1]]]"#
        );
    }
}
