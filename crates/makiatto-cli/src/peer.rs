use argh::FromArgs;
use miette::{Result, miette};

use crate::{config::Profile, machine::corrosion, ssh::SshSession, ui};

/// add an external peer (non-Makiatto node) to the cluster
#[derive(FromArgs)]
#[argh(subcommand, name = "add")]
pub struct AddExternalPeer {
    /// peer name
    #[argh(positional)]
    pub name: String,

    /// wireguard public key
    #[argh(option, long = "wg-pubkey")]
    pub wg_pubkey: String,

    /// public IP address (wireguard endpoint)
    #[argh(option, long = "endpoint")]
    pub endpoint: String,

    /// wireguard address to assign (auto-assigns if not provided)
    #[argh(option, long = "wg-address")]
    pub wg_address: Option<String>,

    /// path to SSH private key (optional)
    #[argh(option, long = "ssh-priv-key")]
    pub key_path: Option<std::path::PathBuf>,
}

/// show `WireGuard` configuration for an external peer
#[derive(FromArgs)]
#[argh(subcommand, name = "wg-config")]
pub struct WgConfig {
    /// peer name
    #[argh(positional)]
    pub name: String,

    /// path to SSH private key (optional)
    #[argh(option, long = "ssh-priv-key")]
    pub key_path: Option<std::path::PathBuf>,
}

/// remove an external peer from the cluster
#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
pub struct RemoveExternalPeer {
    /// peer name
    #[argh(positional)]
    pub name: String,

    /// skip confirmation prompt
    #[argh(switch, long = "force")]
    pub force: bool,

    /// path to SSH private key (optional)
    #[argh(option, long = "ssh-priv-key")]
    pub key_path: Option<std::path::PathBuf>,
}

fn validate_peer_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(miette!("Peer name cannot be empty"));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(miette!(
            "Peer name '{name}' contains invalid characters. Only A-Z, a-z, 0-9, underscores (_), and dashes (-) are allowed",
        ));
    }

    if name.len() > 63 {
        return Err(miette!(
            "Peer name '{name}' is too long. Maximum length is 63 characters",
        ));
    }

    Ok(())
}

fn assign_wireguard_address(profile: &Profile, ssh: &SshSession) -> Result<String> {
    // Collect addresses from local profile
    let mut used_ips: std::collections::HashSet<String> = profile
        .machines
        .iter()
        .map(|m| m.wg_address.to_string())
        .collect();

    // Also get addresses from the database (includes external peers)
    if let Ok(peers) = corrosion::query_peers(ssh) {
        for peer in peers {
            used_ips.insert(peer.wg_address);
        }
    }

    for i in 1..=254 {
        let candidate = format!("10.44.44.{i}");
        if !used_ips.contains(&candidate) {
            return Ok(candidate);
        }
    }

    Err(miette!(
        "No available WireGuard IP addresses in the 10.44.44.0/24 range"
    ))
}

/// Add an external peer to the cluster
///
/// # Errors
/// Returns an error if the peer cannot be added
pub fn add_external_peer(request: &AddExternalPeer, profile: &Profile) -> Result<()> {
    validate_peer_name(&request.name)?;

    if profile.machines.is_empty() {
        return Err(miette!(
            "No machines configured. Initialise at least one machine first with `maki machine init`"
        ));
    }

    // Connect to first available machine to execute the insert
    let machine = &profile.machines[0];
    ui::status(&format!("Connecting to {} to add peer...", machine.name));
    let ssh = SshSession::new(&machine.ssh_target, machine.port, request.key_path.as_ref())?;

    // Check if peer already exists
    if let Ok(Some(_)) = corrosion::query_peer(&ssh, &request.name) {
        return Err(miette!(
            "Peer '{}' already exists in the cluster",
            request.name
        ));
    }

    // Assign WireGuard address if not provided
    let wg_address = match &request.wg_address {
        Some(addr) => addr.clone(),
        None => assign_wireguard_address(profile, &ssh)?,
    };

    ui::header("Adding external peer:");
    ui::field("Name", &request.name);
    ui::field("WireGuard pubkey", &request.wg_pubkey);
    ui::field("WireGuard address", &wg_address);
    ui::field("Endpoint", &request.endpoint);

    // Insert into peers table with is_external = 1
    let sql = format!(
        "INSERT INTO peers (name, latitude, longitude, ipv4, ipv6, wg_public_key, wg_address, is_nameserver, is_external) VALUES ('{}', 0.0, 0.0, '{}', NULL, '{}', '{}', 0, 1)",
        request.name, request.endpoint, request.wg_pubkey, wg_address,
    );

    corrosion::execute_transactions(&ssh, &[sql])?;

    ui::status("External peer added successfully");
    ui::info(&format!(
        "Run `maki peer wg-config {}` to see the WireGuard configuration for this peer",
        request.name
    ));

    Ok(())
}

/// Show `WireGuard` configuration for an external peer
///
/// # Errors
/// Returns an error if the peer is not found or configuration cannot be generated
pub fn show_wg_config(request: &WgConfig, profile: &Profile) -> Result<()> {
    if profile.machines.is_empty() {
        return Err(miette!(
            "No machines configured. Initialise at least one machine first with `maki machine init`"
        ));
    }

    // Connect to first available machine to query peers
    let machine = &profile.machines[0];
    let ssh = SshSession::new(&machine.ssh_target, machine.port, request.key_path.as_ref())?;

    // Find the external peer
    let peer = corrosion::query_peer(&ssh, &request.name)?
        .ok_or_else(|| miette!("Peer '{}' not found in the cluster", request.name))?;

    ui::header(&format!("WireGuard configuration for '{}'", request.name));
    println!();
    println!("[Interface]");
    println!("PrivateKey = <private-key>");
    println!("Address = {}/32", peer.wg_address);
    println!("ListenPort = 51820");
    println!();

    // Get all Makiatto nodes (non-external peers) to add as peers
    let all_peers = corrosion::query_peers(&ssh)?;

    for machine in &profile.machines {
        // Find this machine in the peers list to get its details
        if let Some(node_peer) = all_peers.iter().find(|p| p.name == machine.name.as_ref()) {
            println!("[Peer]  # {}", machine.name);
            println!("PublicKey = {}", node_peer.wg_public_key);
            println!("Endpoint = {}:51820", node_peer.ipv4);
            println!("AllowedIPs = {}/32", node_peer.wg_address);
            println!("PersistentKeepalive = 25");
            println!();
        } else {
            // Fallback to profile data if not in database yet
            println!("[Peer]  # {}", machine.name);
            println!("PublicKey = {}", machine.wg_public_key);
            println!("Endpoint = {}:51820", machine.ipv4);
            println!("AllowedIPs = {}/32", machine.wg_address);
            println!("PersistentKeepalive = 25");
            println!();
        }
    }

    Ok(())
}

/// Remove an external peer from the cluster
///
/// # Errors
/// Returns an error if the peer cannot be removed
pub fn remove_external_peer(request: &RemoveExternalPeer, profile: &Profile) -> Result<()> {
    if profile.machines.is_empty() {
        return Err(miette!("No machines configured"));
    }

    let machine = &profile.machines[0];
    let ssh = SshSession::new(&machine.ssh_target, machine.port, request.key_path.as_ref())?;

    // Check if peer exists
    let _peer = corrosion::query_peer(&ssh, &request.name)?
        .ok_or_else(|| miette!("Peer '{}' not found in the cluster", request.name))?;

    if !request.force {
        ui::warn(&format!(
            "About to remove external peer '{}' from the cluster.",
            request.name
        ));

        let confirm = dialoguer::Confirm::new()
            .with_prompt("Do you want to continue?")
            .default(false)
            .interact()
            .map_err(|e| miette!("Failed to read confirmation: {e}"))?;

        if !confirm {
            ui::info("Removal cancelled");
            return Ok(());
        }
    }

    ui::status(&format!("Removing external peer '{}'", request.name));
    corrosion::delete_peer(&ssh, &request.name)?;
    ui::info(&format!(
        "External peer '{}' removed successfully",
        request.name
    ));

    Ok(())
}
