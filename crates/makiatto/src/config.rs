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

    /// Observability configuration
    #[serde(default)]
    pub o11y: ObservabilityConfig,

    /// Consensus configuration
    #[serde(default)]
    pub consensus: ConsensusConfig,

    /// Certificate renewal configuration
    #[serde(default)]
    pub certificate_renewal: CertificateRenewalConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeConfig {
    /// Unique node name/identifier
    pub name: Arc<str>,

    /// Data directory for this node
    pub data_dir: Arc<Utf8PathBuf>,

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
    /// `WireGuard` endpoint of peer
    pub endpoint: Arc<str>,

    /// `WireGuard` address of peer
    pub address: Arc<str>,

    /// Public key to peer
    pub public_key: Arc<str>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsConfig {
    /// Path to `GeoLite2` database
    pub geolite_path: Arc<Utf8PathBuf>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebConfig {
    /// HTTP server address
    pub http_addr: Arc<str>,

    /// HTTPS server address
    pub https_addr: Arc<str>,

    /// Directory to serve static files from
    pub static_dir: Arc<Utf8PathBuf>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ObservabilityConfig {
    /// Enable tracing export
    #[serde(default = "default_true")]
    pub tracing_enabled: bool,

    /// Enable metrics collection and export
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,

    /// Enable log export
    #[serde(default = "default_true")]
    pub logging_enabled: bool,

    /// OTLP endpoint
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: Arc<str>,

    /// Sampling ratio (0.0 to 1.0)
    #[serde(default = "default_sampling_ratio")]
    pub sampling_ratio: f64,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            tracing_enabled: default_true(),
            metrics_enabled: default_true(),
            logging_enabled: default_true(),
            otlp_endpoint: default_otlp_endpoint(),
            sampling_ratio: default_sampling_ratio(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_otlp_endpoint() -> Arc<str> {
    Arc::from("http://localhost:4317")
}

fn default_sampling_ratio() -> f64 {
    0.1
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ConsensusConfig {
    /// Enable consensus/leader election
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// Leadership lease duration in seconds
    #[serde(default = "default_lease_duration")]
    pub lease_duration: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            heartbeat_interval: default_heartbeat_interval(),
            lease_duration: default_lease_duration(),
        }
    }
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_lease_duration() -> u64 {
    120
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateRenewalConfig {
    /// Enable automatic certificate renewal
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// How often to check certificates (seconds)
    #[serde(default = "default_check_interval")]
    pub check_interval: u64,

    /// Days before expiry to renew
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold: u32,

    /// Maximum renewal retry attempts
    #[serde(default = "default_max_retry_attempts")]
    pub max_retry_attempts: u32,

    /// ACME account email (optional but recommended)
    #[serde(default)]
    pub acme_email: String,

    /// ACME directory URL
    #[serde(default = "default_acme_directory_url")]
    pub acme_directory_url: String,
}

impl Default for CertificateRenewalConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            check_interval: default_check_interval(),
            renewal_threshold: default_renewal_threshold(),
            max_retry_attempts: default_max_retry_attempts(),
            acme_email: String::new(),
            acme_directory_url: default_acme_directory_url(),
        }
    }
}

fn default_check_interval() -> u64 {
    3600 // 1 hour
}

fn default_renewal_threshold() -> u32 {
    30 // days
}

fn default_max_retry_attempts() -> u32 {
    5
}

fn default_acme_directory_url() -> String {
    // Use staging by default for safety
    "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
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
        Utf8PathBuf::from("/etc/makiatto/config.toml"),
        Utf8PathBuf::from("/etc/makiatto.toml"),
        #[cfg(debug_assertions)]
        Utf8PathBuf::from("./tests/fixtures/makiatto-local.toml"),
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
