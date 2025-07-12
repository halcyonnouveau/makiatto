#![allow(dead_code)]
use miette::{Result, miette};

use crate::{config::MachineConfig, ssh::SshSession};

/// Represents a peer from the database
#[derive(Debug, Clone)]
pub struct Peer {
    pub id: i64,
    pub name: String,
    pub latitude: f64,
    pub longitude: f64,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub wg_public_key: String,
    pub wg_address: String,
}

/// Insert a new peer into the database via SSH
pub fn insert_peer(ssh: &SshSession, machine: &MachineConfig) -> Result<()> {
    let latitude = machine.latitude.unwrap_or(0.0);
    let longitude = machine.longitude.unwrap_or(0.0);
    let ipv6_value = machine
        .ipv6
        .as_ref()
        .map_or_else(|| "NULL".to_string(), |s| format!("\\\"{s}\\\""));

    let sql = format!(
        "INSERT INTO peers (name, latitude, longitude, ipv4, ipv6, wg_public_key, wg_address) VALUES (\\\"{}\\\", {}, {}, \\\"{}\\\", {}, \\\"{}\\\", \\\"{}\\\")",
        machine.name,
        latitude,
        longitude,
        machine.ipv4,
        ipv6_value,
        machine.wg_public_key,
        machine.wg_address,
    );

    let json_payload = format!("[\"{sql}\"]");

    let cmd = format!(
        "curl -s -X POST -H 'Content-Type: application/json' -d '{json_payload}' http://127.0.0.1:8181/v1/transactions"
    );

    let response = ssh
        .exec(&cmd)
        .map_err(|e| miette!("Failed to insert peer: {e}"))?;

    if !response.contains("\"rows_affected\"") || response.contains("\"error\"") {
        return Err(miette!("Corrosion API error: {response}"));
    }

    Ok(())
}

/// Query all peers from the database via SSH
pub fn query_peers(ssh: &SshSession) -> Result<Vec<Peer>> {
    let sql =
        "SELECT id, name, latitude, longitude, ipv4, ipv6, wg_public_key, wg_address FROM peers;";
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
        if parts.len() != 12 {
            return Err(miette!(
                "Invalid peer data format: expected 12 fields, got {}",
                parts.len()
            ));
        }

        let peer = Peer {
            id: parts[0]
                .parse()
                .map_err(|e| miette!("Invalid peer ID: {e}"))?,
            name: parts[1].to_string(),
            latitude: parts[2]
                .parse()
                .map_err(|e| miette!("Invalid latitude: {e}"))?,
            longitude: parts[3]
                .parse()
                .map_err(|e| miette!("Invalid longitude: {e}"))?,
            ipv4: parts[4].to_string(),
            ipv6: if parts[5].is_empty() || parts[5] == "NULL" {
                None
            } else {
                Some(parts[5].to_string())
            },
            wg_public_key: parts[6].to_string(),
            wg_address: parts[7].to_string(),
        };

        peers.push(peer);
    }

    Ok(peers)
}

/// Update an existing peer in the database via SSH
pub fn update_peer(ssh: &SshSession, machine: &MachineConfig) -> Result<()> {
    let latitude = machine.latitude.unwrap_or(0.0);
    let longitude = machine.longitude.unwrap_or(0.0);
    let ipv6_value = machine
        .ipv6
        .as_ref()
        .map_or_else(|| "NULL".to_string(), |s| format!("'{s}'"));

    let sql = format!(
        "UPDATE peers SET latitude = {}, longitude = {}, ipv4 = '{}', ipv6 = {}, wg_public_key = '{}', wg_address = '{}', updated_at = unixepoch() WHERE name = '{}';",
        latitude,
        longitude,
        machine.ipv4,
        ipv6_value,
        machine.wg_public_key,
        machine.wg_address,
        machine.name
    );

    let cmd = format!("sudo -u makiatto sqlite3 /var/makiatto/cluster.db \"{sql}\"");
    ssh.exec(&cmd)
        .map_err(|e| miette!("Failed to update peer in database: {e}"))?;

    Ok(())
}
