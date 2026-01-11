#![allow(dead_code)]
use miette::{IntoDiagnostic, Result, miette};

use crate::{config::Machine, ssh::SshSession};

/// Represents a peer from the database
#[derive(Debug, Clone)]
pub struct Peer {
    pub name: String,
    pub latitude: f64,
    pub longitude: f64,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub wg_public_key: String,
    pub wg_address: String,
}

/// Insert a new peer into the database via SSH
///
/// # Errors
/// Returns an error if the SSH command fails or if the database operation fails
pub fn insert_peer(ssh: &SshSession, machine: &Machine) -> Result<()> {
    let latitude = machine.latitude.unwrap_or(0.0);
    let longitude = machine.longitude.unwrap_or(0.0);
    let ipv6_value = machine
        .ipv6
        .as_ref()
        .map_or_else(|| "NULL".to_string(), |s| format!("'{s}'"));

    let sql = format!(
        "INSERT INTO peers (name, latitude, longitude, ipv4, ipv6, wg_public_key, wg_address, is_nameserver, is_external) VALUES ('{}', {}, {}, '{}', {}, '{}', '{}', {}, 0)",
        machine.name,
        latitude,
        longitude,
        machine.ipv4,
        ipv6_value,
        machine.wg_public_key,
        machine.wg_address,
        u8::from(machine.is_nameserver)
    );

    execute_transactions(ssh, &[sql])?;

    Ok(())
}

/// Delete a peer from the database via SSH
///
/// # Errors
/// Returns an error if the SSH command fails or if the database operation fails
pub fn delete_peer(ssh: &SshSession, name: &str) -> Result<()> {
    let sql = format!("DELETE FROM peers WHERE name = '{name}'");
    execute_transactions(ssh, &[sql])?;
    Ok(())
}

/// Query all peers from the database (excluding external peers)
///
/// # Errors
/// Returns an error if the SSH command fails, database query fails, or if the data format is invalid
pub fn query_peers(ssh: &SshSession) -> Result<Vec<Peer>> {
    let sql = "SELECT name, latitude, longitude, ipv4, ipv6, wg_public_key, wg_address FROM peers WHERE is_external = 0;";
    let cmd = format!("sudo -u makiatto sqlite3 /var/makiatto/cluster.db -separator '|' \"{sql}\"");

    let output = ssh
        .exec(&cmd)
        .map_err(|e| miette!("Failed to query peers from database: {e}"))?;

    let mut peers = Vec::new();
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 7 {
            return Err(miette!(
                "Invalid peer data format: expected 7 fields, got {}",
                parts.len()
            ));
        }

        let peer = Peer {
            name: parts[0].to_string(),
            latitude: parts[1]
                .parse()
                .map_err(|e| miette!("Invalid latitude: {e}"))?,
            longitude: parts[2]
                .parse()
                .map_err(|e| miette!("Invalid longitude: {e}"))?,
            ipv4: parts[3].to_string(),
            ipv6: if parts[4].is_empty() || parts[4] == "NULL" {
                None
            } else {
                Some(parts[4].to_string())
            },
            wg_public_key: parts[5].to_string(),
            wg_address: parts[6].to_string(),
        };

        peers.push(peer);
    }

    Ok(peers)
}

/// Query all peers from the database (including external peers)
///
/// # Errors
/// Returns an error if the SSH command fails, database query fails, or if the data format is invalid
pub fn query_all_peers(ssh: &SshSession) -> Result<Vec<Peer>> {
    let sql = "SELECT name, latitude, longitude, ipv4, ipv6, wg_public_key, wg_address FROM peers;";
    let cmd = format!("sudo -u makiatto sqlite3 /var/makiatto/cluster.db -separator '|' \"{sql}\"");

    let output = ssh
        .exec(&cmd)
        .map_err(|e| miette!("Failed to query peers from database: {e}"))?;

    let mut peers = Vec::new();
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 7 {
            return Err(miette!(
                "Invalid peer data format: expected 7 fields, got {}",
                parts.len()
            ));
        }

        let peer = Peer {
            name: parts[0].to_string(),
            latitude: parts[1]
                .parse()
                .map_err(|e| miette!("Invalid latitude: {e}"))?,
            longitude: parts[2]
                .parse()
                .map_err(|e| miette!("Invalid longitude: {e}"))?,
            ipv4: parts[3].to_string(),
            ipv6: if parts[4].is_empty() || parts[4] == "NULL" {
                None
            } else {
                Some(parts[4].to_string())
            },
            wg_public_key: parts[5].to_string(),
            wg_address: parts[6].to_string(),
        };

        peers.push(peer);
    }

    Ok(peers)
}

/// Query a peer by name from the database
///
/// # Errors
/// Returns an error if the SSH command fails, database query fails, or if the data format is invalid
pub fn query_peer(ssh: &SshSession, name: &str) -> Result<Option<Peer>> {
    let sql = format!(
        "SELECT wg_public_key, wg_address, ipv4, ipv6, latitude, longitude FROM peers WHERE name = '{name}'",
    );
    let cmd = format!("sqlite3 /var/makiatto/cluster.db \"{sql}\"");

    let output = ssh
        .exec(&cmd)
        .map_err(|e| miette!("Failed to query peer from database: {e}"))?;

    if output.trim().is_empty() {
        return Ok(None);
    }

    let parts: Vec<&str> = output.trim().split('|').collect();
    if parts.len() != 6 {
        return Err(miette!(
            "Invalid peer data format: expected 6 fields, got {}",
            parts.len()
        ));
    }

    let peer = Peer {
        name: name.to_string(),
        wg_public_key: parts[0].to_string(),
        wg_address: parts[1].to_string(),
        ipv4: parts[2].to_string(),
        ipv6: if parts[3].is_empty() || parts[3] == "NULL" {
            None
        } else {
            Some(parts[3].to_string())
        },
        latitude: parts[4]
            .parse()
            .map_err(|e| miette!("Invalid latitude: {e}"))?,
        longitude: parts[5]
            .parse()
            .map_err(|e| miette!("Invalid longitude: {e}"))?,
    };

    Ok(Some(peer))
}

/// Execute multiple SQL transactions via Corrosion API
///
/// # Errors
/// Returns an error if the HTTP request fails or the API returns an error
pub fn execute_transactions(ssh: &SshSession, sqls: &[String]) -> Result<()> {
    if sqls.is_empty() {
        return Ok(());
    }

    let json_payload = serde_json::to_string(sqls).into_diagnostic()?;
    // need to escape backslashes and quotes for passing through SSH
    let escaped_payload = json_payload.replace('\\', "\\\\").replace('"', "\\\"");

    let cmd = format!(
        "curl -s -X POST -H 'Content-Type: application/json' -d \"{escaped_payload}\" http://127.0.0.1:8181/v1/transactions",
    );

    let response = ssh
        .exec(&cmd)
        .map_err(|e| miette!("Failed to execute transactions: {}", e))?;

    if response.contains("\"error\"") || !response.contains("\"rows_affected\"") {
        return Err(miette!("Corrosion API error: {}", response));
    }

    Ok(())
}
