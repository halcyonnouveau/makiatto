use std::sync::Arc;

use camino::Utf8PathBuf;
use miette::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Node configuration
    pub node: NodeConfig,

    /// Corrosion configuration
    pub corrosion: corro_types::config::Config,

    /// Wireguard configuration
    pub wireguard: WireguardConfig,

    /// DNS server configuration
    pub dns: DnsConfig,

    /// Web server configuration
    pub web: WebConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeConfig {
    /// Unique node name/identifier
    pub name: Arc<str>,

    /// Data directory for this node
    pub data_dir: Utf8PathBuf,

    /// Whether this node should act as a nameserver
    pub is_nameserver: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireguardConfig {
    /// `WireGuard` interface name
    pub interface: Arc<str>,

    /// This node's `WireGuard` IP address (auto-assigned)
    pub address: Arc<str>,

    /// `WireGuard` public key (auto-generated)
    pub public_key: Arc<str>,

    /// `WireGuard` private key (auto-generated)
    pub private_key: Arc<str>,

    /// Bootstrap `WireGuard` peers
    #[serde(default)]
    pub bootstrap: Arc<[Bootstrap]>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Bootstrap {
    /// Public key to peer
    pub public_key: Arc<str>,

    /// `WireGuard` endpoint of peer
    pub endpoint: Arc<str>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsConfig {
    /// DNS server bind address
    pub addr: Arc<str>,

    /// Path to `GeoLite2` database
    pub geolite_path: Utf8PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebConfig {
    /// HTTP server bind address
    pub http_addr: Arc<str>,

    /// HTTPS server bind address
    pub https_addr: Arc<str>,

    /// Directory to serve static files from
    pub static_dir: Utf8PathBuf,
}

impl Config {
    /// Load configuration from file
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed
    pub fn load_from_file(path: &Utf8PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| miette::miette!("Failed to read config file: {}", e))?;

        toml::from_str(&content).map_err(|e| miette::miette!("Failed to parse config: {}", e))
    }
}

/// Load configuration from default locations
///
/// # Errors
/// Returns an error if no config file is found or if parsing fails
pub fn load() -> Result<Config> {
    let config_paths = [
        Utf8PathBuf::from("/etc/makiatto/makiatto.toml"),
        Utf8PathBuf::from("/etc/makiatto.toml"),
        Utf8PathBuf::from("./makiatto-daemon.toml"),
    ];

    for path in &config_paths {
        if path.exists() {
            return Config::load_from_file(path);
        }
    }

    Err(miette::miette!(
        "No makiatto config found. Run 'makiatto-cli machine init' first to set up this node."
    ))
}
