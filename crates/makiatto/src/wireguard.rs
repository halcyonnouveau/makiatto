use std::{str::FromStr, sync::Arc};

#[cfg(not(target_os = "macos"))]
use defguard_wireguard_rs::Kernel;
#[cfg(target_os = "macos")]
use defguard_wireguard_rs::Userspace;
use defguard_wireguard_rs::{
    InterfaceConfiguration, WGApi, WireguardInterfaceApi, host::Peer, key::Key, net::IpAddrMask,
};
use miette::{Result, miette};
use tracing::info;

use crate::{
    config::{Config, WireguardConfig},
    constants::WIREGUARD_PORT,
    corrosion, utils,
};

#[cfg(not(target_os = "macos"))]
pub type Wireguard = WireguardGeneric<Kernel>;
#[cfg(target_os = "macos")]
pub type Wireguard = WireguardGeneric<Userspace>;

pub struct WireguardGeneric<T> {
    api: WGApi<T>,
}

impl<T> WireguardGeneric<T>
where
    WGApi<T>: WireguardInterfaceApi,
{
    /// Set up the `WireGuard` interface
    ///
    /// # Errors
    /// Returns an error if the interface cannot be created or configured
    pub fn new(config: &WireguardConfig, peers: Option<Arc<[corrosion::Peer]>>) -> Result<Self> {
        if utils::is_container() {
            info!(
                "Container environment detected - skipping WireGuard interface '{}' setup",
                config.interface
            );
            let wgapi = WGApi::<T>::new(config.interface.to_string())
                .map_err(|e| miette!("Failed to create WireGuard API: {}", e))?;
            return Ok(Self { api: wgapi });
        }

        info!("Setting up WireGuard interface '{}'", config.interface);

        let wgapi = WGApi::<T>::new(config.interface.to_string())
            .map_err(|e| miette!("Failed to create WireGuard API: {}", e))?;

        if Self::check_interface_exists(&wgapi) {
            wgapi
                .remove_interface()
                .map_err(|e| miette!("Failed to remove existing interface: {}", e))?;
        }

        wgapi
            .create_interface()
            .map_err(|e| miette!("Failed to create WireGuard interface: {}", e))?;

        info!("Created WireGuard interface '{}'", config.interface);

        let address_mask = IpAddrMask::from_str(&config.address)
            .map_err(|e| miette!("Invalid WireGuard address format: {}", e))?;

        let interface_config = InterfaceConfiguration {
            name: config.interface.to_string(),
            prvkey: config.private_key.to_string(),
            addresses: vec![address_mask],
            port: WIREGUARD_PORT.into(),
            peers: vec![],
            mtu: None,
        };

        info!("Configuring interface with address {}", config.address);

        wgapi
            .configure_interface(&interface_config)
            .map_err(|e| miette!("Failed to configure WireGuard interface: {}", e))?;

        let output = std::process::Command::new("sudo")
            .args(["ip", "link", "set", &config.interface, "up"])
            .output()
            .map_err(|e| miette!("Failed to execute ip command: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(miette!("Failed to bring up interface: {}", stderr));
        }

        info!(
            "WireGuard interface '{}' configured and started",
            config.interface
        );

        let wireguard = Self { api: wgapi };

        if let Some(corrosion_peers) = peers
            && !corrosion_peers.is_empty()
        {
            info!(
                "Adding {} peers from Corrosion database",
                corrosion_peers.len()
            );
            for peer in corrosion_peers.iter() {
                let endpoint = format!("{}:{}", peer.ipv4, peer.wg_port);
                match wireguard.add_peer(&endpoint, &peer.wg_address, &peer.wg_public_key) {
                    Ok(()) => info!("Added peer from database: {}", peer.name),
                    Err(e) => {
                        tracing::error!("Failed to add peer {}: {e}", peer.name);
                    }
                }
            }
        } else {
            info!("No peers found in Corrosion database, falling back to bootstrap peers");
            Self::add_bootstrap_peers(&wireguard, config);
        }

        Ok(wireguard)
    }

    /// Add a peer to the `WireGuard` interface
    ///
    /// # Errors
    /// Returns an error if the peer cannot be added
    pub fn add_peer(&self, endpoint: &str, address: &str, public_key: &str) -> Result<()> {
        if utils::is_container() {
            info!("Container environment detected - skipping peer addition");
            return Ok(());
        }

        let peer_key =
            Key::from_str(public_key).map_err(|e| miette!("Invalid peer public key: {e}"))?;

        let mut peer = Peer::new(peer_key);

        peer.endpoint = Some(
            endpoint
                .parse()
                .map_err(|e| miette!("Invalid endpoint format: {e}"))?,
        );

        let addr = IpAddrMask::from_str(&format!("{address}/32"))
            .map_err(|e| miette!("Unable to create addr mask: {e}"))?;

        peer.allowed_ips.push(addr);

        self.api
            .configure_peer(&peer)
            .map_err(|e| miette!("Failed to configure peer: {e}"))?;

        Ok(())
    }

    /// Clean up the `WireGuard` interface on shutdown
    ///
    /// # Errors
    /// Returns an error if the interface cannot be removed
    pub fn cleanup_interface(self) -> Result<()> {
        if utils::is_container() {
            info!("Container environment detected - skipping WireGuard interface cleanup",);
            return Ok(());
        }

        info!("Cleaning up WireGuard interface");

        if Self::check_interface_exists(&self.api) {
            self.api
                .remove_interface()
                .map_err(|e| miette!("Failed to remove WireGuard interface: {}", e))?;
            info!("Removed WireGuard interface");
        } else {
            info!("WireGuard interface already removed");
        }

        Ok(())
    }

    fn add_bootstrap_peers(wireguard: &Self, config: &WireguardConfig) {
        if !config.bootstrap.is_empty() {
            info!("Bootstrapping {} peers", config.bootstrap.len());
            for bootstrap_peer in config.bootstrap.iter() {
                match wireguard.add_peer(
                    &bootstrap_peer.address,
                    &bootstrap_peer.endpoint,
                    &bootstrap_peer.public_key,
                ) {
                    Ok(()) => info!("Added bootstrap peer: {}", bootstrap_peer.address),
                    Err(e) => {
                        tracing::error!(
                            "Failed to add bootstrap peer {}: {e}",
                            bootstrap_peer.address,
                        );
                    }
                }
            }
        }
    }

    fn check_interface_exists(wgapi: &WGApi<T>) -> bool
    where
        WGApi<T>: WireguardInterfaceApi,
    {
        wgapi.read_interface_data().is_ok()
    }
}

/// Set up the `WireGuard` interface using platform-specific implementation
///
/// # Errors
/// Returns an error if the interface cannot be created or configured
pub fn setup_wireguard(
    config: &Config,
    peers: Option<Arc<[corrosion::Peer]>>,
) -> Result<Wireguard> {
    Wireguard::new(&config.wireguard, peers)
}

/// Clean up the `WireGuard` interface
///
/// # Errors
/// Returns an error if the interface cannot be removed
pub fn cleanup_wireguard(wireguard: Wireguard) -> Result<()> {
    wireguard.cleanup_interface()
}
