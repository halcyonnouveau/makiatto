use std::path::PathBuf;

use argh::FromArgs;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use miette::{Result, miette};
use x25519_dalek::{PublicKey, StaticSecret};

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

    /// just install, don't save config (optional)
    #[argh(switch, long = "install-only")]
    pub install_only: bool,
}

pub async fn init_machine(
    request: InitMachine,
    global_config: &mut GlobalConfig,
) -> Result<SshSession> {
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
    let (wg_private_key, wg_public_key) = generate_wireguard_keypair()?;
    let wg_endpoint = format!("{host}:51820");

    ui::header("Initialising machine:");
    ui::field("Name", &request.name);
    ui::field("SSH target", &request.ssh_target);
    ui::field("Is nameserver", &is_nameserver.to_string());
    ui::field("WireGuard public key", &wg_public_key);
    ui::field("WireGuard address", &wg_address);
    ui::field("WireGuard endpoint", &wg_endpoint);

    let machine_config = MachineConfig {
        name: request.name.clone(),
        ssh_target: request.ssh_target.clone(),
        is_nameserver,
        wg_public_key: wg_public_key.clone(),
        wg_address: wg_address.clone(),
        wg_endpoint,
    };

    let session = provision::install_makiatto(
        global_config,
        &machine_config,
        &wg_private_key,
        &request.binary_path,
        &request.key_path,
    )?;

    global_config.add_machine(machine_config.clone());

    // TODO: if not first node, add machine to cluster
    // - ssh to existing node in cluster
    // - add new node wireguard config to corrosion db
    // - get peers table from existing corrosion db
    // - add peers table to new node

    ui::status("Machine installation completed successfully");

    Ok(session)
}

pub fn generate_wireguard_keypair() -> Result<(String, String)> {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    Ok((
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.to_bytes()),
    ))
}

fn assign_wireguard_address(global_config: &GlobalConfig) -> Result<String> {
    let used_ips: std::collections::HashSet<String> = global_config
        .machines
        .iter()
        .map(|m| m.wg_address.clone())
        .collect();

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
                    name: "node1".to_string(),
                    ssh_target: "user@host1".to_string(),
                    is_nameserver: false,
                    wg_public_key: "key1".to_string(),
                    wg_address: "10.44.44.1".to_string(),
                    wg_endpoint: "0.0.0.0:9090".to_string(),
                },
                MachineConfig {
                    name: "node2".to_string(),
                    ssh_target: "user@host2".to_string(),
                    is_nameserver: false,
                    wg_public_key: "key2".to_string(),
                    wg_address: "10.44.44.3".to_string(),
                    wg_endpoint: "0.0.0.0:9090".to_string(),
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
                name: format!("node{}", i),
                ssh_target: format!("user@host{}", i),
                is_nameserver: false,
                wg_public_key: format!("key{}", i),
                wg_address: format!("10.44.44.{}", i),
                wg_endpoint: format!("0.0.0.0:{}", i),
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
