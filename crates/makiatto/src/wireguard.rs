use std::{str::FromStr, sync::Arc};

#[cfg(not(target_os = "macos"))]
use defguard_wireguard_rs::Kernel;
#[cfg(target_os = "macos")]
use defguard_wireguard_rs::Userspace;
use defguard_wireguard_rs::{
    InterfaceConfiguration, WGApi, WireguardInterfaceApi, host::Peer, key::Key, net::IpAddrMask,
};
use miette::{Result, miette};
use tokio::{
    sync::{mpsc, oneshot},
    task::spawn_blocking,
};
use tracing::{error, info};

use crate::{
    config::{Config, WireguardConfig},
    r#const::WIREGUARD_PORT,
    corrosion,
};

#[derive(Debug)]
pub enum WireguardCommand {
    AddPeer {
        endpoint: String,
        address: String,
        public_key: String,
        response: oneshot::Sender<Result<()>>,
    },
    RemovePeer {
        public_key: String,
        address: String,
        response: oneshot::Sender<Result<()>>,
    },
}

#[derive(Clone)]
pub struct WireguardManager {
    tx: mpsc::UnboundedSender<WireguardCommand>,
}

impl WireguardManager {
    /// Add a peer to the `WireGuard` interface
    ///
    /// # Errors
    /// Returns an error if the manager task has stopped or the peer cannot be added
    pub async fn add_peer(&self, endpoint: &str, address: &str, public_key: &str) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();

        self.tx
            .send(WireguardCommand::AddPeer {
                endpoint: endpoint.to_string(),
                address: address.to_string(),
                public_key: public_key.to_string(),
                response: response_tx,
            })
            .map_err(|_| miette!("WireGuard manager task has stopped"))?;

        response_rx
            .await
            .map_err(|_| miette!("Failed to receive response from WireGuard manager"))?
    }

    /// Remove a peer from the `WireGuard` interface
    ///
    /// # Errors
    /// Returns an error if the manager task has stopped or the peer cannot be removed
    pub async fn remove_peer(&self, address: &str, public_key: &str) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();

        self.tx
            .send(WireguardCommand::RemovePeer {
                public_key: public_key.to_string(),
                address: address.to_string(),
                response: response_tx,
            })
            .map_err(|_| miette!("WireGuard manager task has stopped"))?;

        response_rx
            .await
            .map_err(|_| miette!("Failed to receive response from WireGuard manager"))?
    }
}

#[cfg(not(target_os = "macos"))]
type Wireguard = WireguardGeneric<Kernel>;
#[cfg(target_os = "macos")]
type Wireguard = WireguardGeneric<Userspace>;

struct WireguardGeneric<T> {
    api: WGApi<T>,
    config: WireguardConfig,
}

impl<T> WireguardGeneric<T>
where
    WGApi<T>: WireguardInterfaceApi,
{
    /// Set up the `WireGuard` interface
    ///
    /// # Errors
    /// Returns an error if the interface cannot be created or configured
    pub fn new(
        config: &WireguardConfig,
        peers: Option<Arc<[corrosion::schema::Peer]>>,
    ) -> Result<Self> {
        if is_container() {
            info!(
                "Container environment detected - skipping WireGuard interface '{}' setup",
                config.interface
            );
            let wgapi = WGApi::<T>::new(config.interface.to_string())
                .map_err(|e| miette!("Failed to create WireGuard API: {e}"))?;
            return Ok(Self {
                api: wgapi,
                config: config.to_owned(),
            });
        }

        info!("Setting up WireGuard interface '{}'", config.interface);

        let wgapi = WGApi::<T>::new(config.interface.to_string())
            .map_err(|e| miette!("Failed to create WireGuard API: {e}"))?;

        if Self::check_interface_exists(&wgapi) {
            wgapi
                .remove_interface()
                .map_err(|e| miette!("Failed to remove existing interface: {e}"))?;
        }

        wgapi
            .create_interface()
            .map_err(|e| miette!("Failed to create WireGuard interface: {e}"))?;

        info!("Created WireGuard interface '{}'", config.interface);

        let address_mask = IpAddrMask::from_str(&config.address)
            .map_err(|e| miette!("Invalid WireGuard address format: {e}"))?;

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
            .map_err(|e| miette!("Failed to configure WireGuard interface: {e}"))?;

        let output = std::process::Command::new("sudo")
            .args(["ip", "link", "set", &config.interface, "up"])
            .output()
            .map_err(|e| miette!("Failed to execute ip command: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(miette!("Failed to bring up interface: {stderr}"));
        }

        info!(
            "WireGuard interface '{}' configured and started",
            config.interface
        );

        let wireguard = Self {
            api: wgapi,
            config: config.to_owned(),
        };

        if let Some(corrosion_peers) = peers
            && !corrosion_peers.is_empty()
        {
            info!(
                "Adding {} peers from Corrosion database",
                corrosion_peers.len()
            );
            for peer in corrosion_peers.iter() {
                let endpoint = format!("{}:{WIREGUARD_PORT}", peer.ipv4);
                match wireguard.add_peer(&endpoint, &peer.wg_address, &peer.wg_public_key) {
                    Ok(()) => {}
                    Err(e) => {
                        error!("Failed to add peer {}: {e}", peer.name);
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
        if is_container() {
            info!("Container environment detected - skipping peer addition");
            return Ok(());
        }

        if self.config.public_key.as_str() == public_key {
            return Ok(());
        }

        info!("Adding new peer: {endpoint} -> {address}");

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

        info!("Peer configured successfully");

        let route_output = std::process::Command::new("sudo")
            .args([
                "ip",
                "route",
                "add",
                &format!("{address}/32"),
                "dev",
                &self.config.interface,
            ])
            .output()
            .map_err(|e| miette!("Failed to execute ip route command: {e}"))?;

        if !route_output.status.success() {
            let stderr = String::from_utf8_lossy(&route_output.stderr);
            if !stderr.contains("File exists") {
                return Err(miette!("Failed to add route for peer {address}: {stderr}"));
            }
        }

        info!("Added route for peer: {address}/32");

        Ok(())
    }

    /// Remove a peer from the `WireGuard` interface
    ///
    /// # Errors
    /// Returns an error if the peer cannot be removed
    pub fn remove_peer(&self, address: &str, public_key: &str) -> Result<()> {
        if is_container() {
            info!("Container environment detected - skipping peer removal");
            return Ok(());
        }

        if self.config.public_key.as_str() == public_key {
            return Ok(());
        }

        info!("Removing peer: {public_key}");

        let peer_key =
            Key::from_str(public_key).map_err(|e| miette!("Invalid peer public key: {e}"))?;

        self.api
            .remove_peer(&peer_key)
            .map_err(|e| miette!("Failed to remove peer: {e}"))?;

        let route_output = std::process::Command::new("sudo")
            .args([
                "ip",
                "route",
                "del",
                &format!("{address}/32"),
                "dev",
                &self.config.interface,
            ])
            .output()
            .map_err(|e| miette!("Failed to execute ip route command: {e}"))?;

        if route_output.status.success() {
            info!("Removed route for peer: {address}/32");
        } else {
            let stderr = String::from_utf8_lossy(&route_output.stderr);
            if !stderr.contains("No such process") {
                error!("Failed to remove route for peer {address}: {stderr}");
            }
        }

        Ok(())
    }

    /// Clean up the `WireGuard` interface on shutdown
    ///
    /// # Errors
    /// Returns an error if the interface cannot be removed
    pub fn cleanup_interface(&self) -> Result<()> {
        if is_container() {
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
                    &bootstrap_peer.endpoint,
                    &bootstrap_peer.address,
                    &bootstrap_peer.public_key,
                ) {
                    Ok(()) => info!("Added bootstrap peer: {}", bootstrap_peer.address),
                    Err(e) => {
                        error!(
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
pub async fn setup(
    config: &Config,
) -> Result<(WireguardManager, tokio::task::JoinHandle<Result<()>>)> {
    // try to get other peers from database
    let peers = {
        match sqlx::SqlitePool::connect(&format!("sqlite:{}", config.corrosion.db.path)).await {
            Ok(pool) => {
                let rows_result = sqlx::query!(
                    "SELECT name, wg_public_key, wg_address, ipv4, ipv6, latitude, longitude, is_nameserver, fs_port
                    FROM peers
                        WHERE name != ?",
                    config.node.name
                )
                .fetch_all(&pool)
                .await;

                match rows_result {
                    Ok(rows) => {
                        let peers: Vec<corrosion::schema::Peer> = rows
                            .into_iter()
                            .map(|row| corrosion::schema::Peer {
                                name: Arc::from(row.name),
                                ipv4: Arc::from(row.ipv4),
                                ipv6: row.ipv6.map(Arc::from),
                                wg_public_key: Arc::from(row.wg_public_key),
                                wg_address: Arc::from(row.wg_address),
                                latitude: row.latitude,
                                longitude: row.longitude,
                                is_nameserver: row.is_nameserver != 0,
                                fs_port: row.fs_port,
                            })
                            .collect();
                        Some(peers.into())
                    }
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    };

    let wg_interface = Wireguard::new(&config.wireguard, peers)?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let manager = WireguardManager { tx };

    let handle = spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();

        loop {
            let Some(command) = rt.block_on(rx.recv()) else {
                break;
            };

            match command {
                WireguardCommand::AddPeer {
                    endpoint,
                    address,
                    public_key,
                    response,
                } => {
                    let result = wg_interface.add_peer(&endpoint, &address, &public_key);
                    let _ = response.send(result);
                }
                WireguardCommand::RemovePeer {
                    public_key,
                    address,
                    response,
                } => {
                    let result = wg_interface.remove_peer(&address, &public_key);
                    let _ = response.send(result);
                }
            }
        }

        wg_interface.cleanup_interface()
    });

    Ok((manager, handle))
}

/// Clean up the `WireGuard` interface
///
/// # Errors
/// Returns an error if the interface cannot be removed
pub async fn cleanup_wireguard(handle: tokio::task::JoinHandle<Result<()>>) -> Result<()> {
    // The handle will automatically cleanup when the channel is dropped
    handle
        .await
        .map_err(|e| miette!("WireGuard task panicked: {e}"))?
}

fn is_container() -> bool {
    if cfg!(debug_assertions) {
        std::path::Path::new("/.dockerenv").exists()
            || std::path::Path::new("/run/.containerenv").exists()
    } else {
        false
    }
}
