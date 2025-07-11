use std::{path::PathBuf, sync::Arc};

use argh::FromArgs;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use miette::{Result, miette};
use x25519_dalek::{PublicKey, StaticSecret};

mod corrosion;
mod geolocation;
mod provision;

use crate::{
    config::{GlobalConfig, MachineConfig},
    ssh::{self, SshSession},
    ui,
};

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

/// Initialize a new makiatto node by installing and configuring the daemon
///
/// # Errors
/// Returns an error if SSH connection fails, installation fails, or configuration is invalid
pub fn init_machine(request: &InitMachine, global_config: &mut GlobalConfig) -> Result<SshSession> {
    if global_config.find_machine(&request.name).is_some() {
        if request.override_existing {
            ui::info(&format!(
                "Overriding existing machine configuration for '{}'",
                request.name
            ));
            global_config.remove_machine(&request.name);
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
        global_config
            .machines
            .iter()
            .filter(|m| m.is_nameserver)
            .count()
            < 3
    };

    let (_user, host, _port) = ssh::parse_ssh_target(&request.ssh_target)?;
    let wg_address = assign_wireguard_address(global_config)?;
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

    let machine_config = MachineConfig {
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
        global_config,
        &machine_config,
        &wg_private_key,
        request.binary_path.as_ref(),
        request.key_path.as_ref(),
    )?;

    global_config.add_machine(machine_config.clone());

    if global_config.machines.len() > 1 {
        ui::status("Adding machine to cluster...");

        if let Some(existing_machine) = global_config.machines.iter().nth_back(1) {
            ui::action(&format!(
                "Connecting to `{}` to add `{}` as a peer",
                existing_machine.name, machine_config.name
            ));

            let existing_ssh =
                SshSession::new(&existing_machine.ssh_target, request.key_path.as_ref())?;

            corrosion::insert_peer(&existing_ssh, &machine_config)?;
        }
    }

    ui::status("Machine installation completed successfully");

    Ok(session)
}

fn generate_wireguard_keypair() -> (String, String) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    (
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.to_bytes()),
    )
}

fn assign_wireguard_address(global_config: &GlobalConfig) -> Result<String> {
    let used_ips: std::collections::HashSet<&str> = global_config
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
        let config = GlobalConfig { machines: vec![] };

        let address = assign_wireguard_address(&config).unwrap();
        assert_eq!(address, "10.44.44.1");
    }

    #[test]
    fn test_assign_wireguard_address_with_existing() {
        let config = GlobalConfig {
            machines: vec![
                MachineConfig {
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
                MachineConfig {
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
            machines.push(MachineConfig {
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

        let config = GlobalConfig { machines };

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
