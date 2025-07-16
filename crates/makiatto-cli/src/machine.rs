use std::{path::PathBuf, sync::Arc};

use argh::FromArgs;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use miette::{Result, miette};
use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};

mod corrosion;
mod geolocation;
mod provision;

use crate::{
    config::{Machine, MachineConfig},
    ssh::{self, SshSession},
    ui,
};

#[derive(Debug, Deserialize)]
struct RemoteConfig {
    node: NodeConfig,
}

#[derive(Debug, Deserialize)]
struct NodeConfig {
    name: String,
    is_nameserver: bool,
}

/// initialise a new makiatto node
#[derive(FromArgs)]
#[argh(subcommand, name = "init")]
pub struct InitMachine {
    /// machine name
    #[argh(positional)]
    pub name: String,

    /// ssh connection string (user@host:port)
    #[argh(positional)]
    pub ssh_target: String,

    /// skip nameserver role (default: auto-assign if <3 nameservers exist)
    #[argh(switch, long = "skip-ns")]
    pub skip_nameserver: bool,

    /// force nameserver role (even if 3+ nameservers already exist)
    #[argh(switch, long = "force-ns")]
    pub force_nameserver: bool,

    /// override existing machine configuration if it exists
    #[argh(switch, long = "override")]
    pub override_existing: bool,

    /// path to makiatto binary (optional)
    #[argh(option, long = "binary-path")]
    pub binary_path: Option<PathBuf>,

    /// path to SSH private key (optional)
    #[argh(option, long = "ssh-priv-key")]
    pub key_path: Option<PathBuf>,
}

/// add an existing makiatto node to the configuration
#[derive(FromArgs)]
#[argh(subcommand, name = "add")]
pub struct AddMachine {
    /// ssh connection string (user@host:port)
    #[argh(positional)]
    pub ssh_target: String,

    /// path to SSH private key (optional)
    #[argh(option, long = "ssh-priv-key")]
    pub key_path: Option<PathBuf>,
}

/// Initialize a new makiatto node by installing and configuring the daemon
///
/// # Errors
/// Returns an error if SSH connection fails, installation fails, or configuration is invalid
pub fn init_machine(
    request: &InitMachine,
    machine_config: &mut MachineConfig,
) -> Result<SshSession> {
    if machine_config.find_machine(&request.name).is_some() {
        if request.override_existing {
            ui::info(&format!(
                "Overriding existing machine configuration for '{}'",
                request.name
            ));
            machine_config.remove_machine(&request.name);
        } else {
            return Err(miette!(
                "Machine '{}' already exists in configuration. Use `--override` to replace it",
                request.name
            ));
        }
    }

    let is_nameserver = if request.force_nameserver {
        true
    } else if request.skip_nameserver {
        false
    } else {
        machine_config
            .machines
            .iter()
            .filter(|m| m.is_nameserver)
            .count()
            < 3
    };

    let (_user, host, _port) = ssh::parse_ssh_target(&request.ssh_target)?;
    let wg_address = assign_wireguard_address(machine_config)?;
    let (wg_private_key, wg_public_key) = generate_wireguard_keypair();

    ui::status("Detecting public IP addresses and location...");
    let (ipv4, ipv6, latitude, longitude) = geolocation::detect_node_info(&host)?;

    ui::header("Initialising machine:");
    ui::field("Name", &request.name);
    ui::field("SSH target", &request.ssh_target);
    ui::field(
        "Is nameserver",
        if is_nameserver { "true" } else { "false" },
    );
    ui::field("WireGuard public key", &wg_public_key);
    ui::field("WireGuard address", &wg_address);
    ui::field("IPv4", &ipv4);

    if let Some(ref v6) = ipv6 {
        ui::field("IPv6", v6);
    } else {
        ui::field("IPv6", "Not available");
    }

    if let (Some(lat), Some(lon)) = (latitude, longitude) {
        ui::field("Location", &format!("{lat:.4}, {lon:.4}"));
    } else {
        ui::field("Location", "Unknown");
    }

    let machine = Machine {
        name: Arc::from(request.name.as_str()),
        ssh_target: Arc::from(request.ssh_target.as_str()),
        is_nameserver,
        wg_public_key: Arc::from(wg_public_key),
        wg_address: Arc::from(wg_address),
        latitude,
        longitude,
        ipv4: Arc::from(ipv4),
        ipv6: ipv6.map(Arc::from),
    };

    let session = provision::install_makiatto(
        machine_config,
        &machine,
        &wg_private_key,
        request.binary_path.as_ref(),
        request.key_path.as_ref(),
    )?;

    machine_config.add_machine(machine.clone());

    if machine_config.machines.len() > 1 {
        ui::status("Adding machine to cluster...");

        if let Some(existing_machine) = machine_config.machines.iter().nth_back(1) {
            ui::action(&format!(
                "Connecting to `{}` to add `{}` as a peer",
                existing_machine.name, machine.name
            ));

            let existing_ssh =
                SshSession::new(&existing_machine.ssh_target, request.key_path.as_ref())?;

            corrosion::insert_peer(&existing_ssh, &machine)?;
        }
    }

    ui::status("Machine installation completed successfully");

    Ok(session)
}

/// Add an existing makiatto node to the configuration
///
/// # Errors
/// Returns an error if SSH connection fails or configuration cannot be retrieved
pub fn add_machine(request: &AddMachine, machine_config: &mut MachineConfig) -> Result<()> {
    ui::status(&format!("Connecting to {}", request.ssh_target));
    let session = SshSession::new(&request.ssh_target, request.key_path.as_ref())?;

    ui::action("Reading remote configuration");

    let config_paths = [
        "/etc/makiatto/makiatto.toml",
        "/etc/makiatto/config.toml",
        "/etc/makiatto.toml",
    ];

    let mut config_content = None;
    for path in &config_paths {
        if let Ok(content) = session.exec(&format!("cat {path}")) {
            config_content = Some(content);
            ui::info(&format!("Found config at {path}"));
            break;
        }
    }

    let config_content = config_content
        .ok_or_else(|| miette!("No makiatto config file found in any of the expected locations"))?;

    let remote_config: RemoteConfig = toml::from_str(&config_content)
        .map_err(|e| miette!("Failed to parse remote config: {e}"))?;

    let node_name = &remote_config.node.name;
    let is_nameserver = remote_config.node.is_nameserver;

    ui::action(&format!("Retrieving peer information for '{node_name}'"));
    let peer = corrosion::query_peer(&session, node_name)?
        .ok_or_else(|| miette!("No peer information found for '{node_name}' in the database"))?;

    let wg_public_key = &peer.wg_public_key;
    let wg_address = &peer.wg_address;
    let ipv4 = &peer.ipv4;
    let ipv6 = peer.ipv6.as_deref();
    let latitude = Some(peer.latitude);
    let longitude = Some(peer.longitude);

    if machine_config.find_machine(node_name).is_some() {
        return Err(miette!(
            "Machine '{node_name}' already exists in configuration",
        ));
    }

    ui::header("Adding machine:");
    ui::field("Name", node_name);
    ui::field("SSH target", &request.ssh_target);
    ui::field(
        "Is nameserver",
        if is_nameserver { "true" } else { "false" },
    );
    ui::field("WireGuard public key", wg_public_key);
    ui::field("WireGuard address", wg_address);
    ui::field("IPv4", ipv4);

    if let Some(v6) = ipv6 {
        ui::field("IPv6", v6);
    } else {
        ui::field("IPv6", "Not available");
    }

    if let (Some(lat), Some(lon)) = (latitude, longitude) {
        ui::field("Location", &format!("{lat:.4}, {lon:.4}"));
    } else {
        ui::field("Location", "Unknown");
    }

    let machine = Machine {
        name: Arc::from(node_name.as_str()),
        ssh_target: Arc::from(request.ssh_target.as_str()),
        is_nameserver,
        wg_public_key: Arc::from(wg_public_key.to_owned()),
        wg_address: Arc::from(wg_address.to_owned()),
        latitude,
        longitude,
        ipv4: Arc::from(ipv4.to_owned()),
        ipv6: ipv6.map(Arc::from),
    };

    machine_config.add_machine(machine);
    ui::status("Machine added successfully");

    Ok(())
}

fn generate_wireguard_keypair() -> (String, String) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    (
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.to_bytes()),
    )
}

fn assign_wireguard_address(machines_config: &MachineConfig) -> Result<String> {
    let used_ips: std::collections::HashSet<&str> = machines_config
        .machines
        .iter()
        .map(|m| m.wg_address.as_ref())
        .collect();

    for i in 1..=254 {
        let candidate = format!("10.44.44.{i}");
        if !used_ips.contains(candidate.as_str()) {
            return Ok(candidate);
        }
    }

    Err(miette!(
        "No available WireGuard IP addresses in the 10.44.44.0/24 range"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_wireguard_address_empty_config() {
        let config = MachineConfig { machines: vec![] };

        let address = assign_wireguard_address(&config).unwrap();
        assert_eq!(address, "10.44.44.1");
    }

    #[test]
    fn test_assign_wireguard_address_with_existing() {
        let config = MachineConfig {
            machines: vec![
                Machine {
                    name: Arc::from("node1"),
                    ssh_target: Arc::from("user@host1"),
                    is_nameserver: false,
                    wg_public_key: Arc::from("key1"),
                    wg_address: Arc::from("10.44.44.1"),
                    latitude: None,
                    longitude: None,
                    ipv4: Arc::from("1.1.1.1"),
                    ipv6: None,
                },
                Machine {
                    name: Arc::from("node2"),
                    ssh_target: Arc::from("user@host2"),
                    is_nameserver: false,
                    wg_public_key: Arc::from("key2"),
                    wg_address: Arc::from("10.44.44.3"),
                    latitude: None,
                    longitude: None,
                    ipv4: Arc::from("2.2.2.2"),
                    ipv6: None,
                },
            ],
        };

        let address = assign_wireguard_address(&config).unwrap();
        assert_eq!(address, "10.44.44.2");
    }

    #[test]
    fn test_assign_wireguard_address_full_subnet() {
        let mut machines = vec![];
        for i in 1..=254 {
            machines.push(Machine {
                name: Arc::from(format!("node{i}")),
                ssh_target: Arc::from(format!("user@host{i}")),
                is_nameserver: false,
                wg_public_key: Arc::from(format!("key{i}")),
                wg_address: Arc::from(format!("10.44.44.{i}")),
                latitude: None,
                longitude: None,
                ipv4: Arc::from(format!(
                    "{}.{}.{}.{}",
                    i % 255,
                    (i + 1) % 255,
                    (i + 2) % 255,
                    (i + 3) % 255
                )),
                ipv6: None,
            });
        }

        let config = MachineConfig { machines };

        let result = assign_wireguard_address(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No available WireGuard IP addresses")
        );
    }
}
