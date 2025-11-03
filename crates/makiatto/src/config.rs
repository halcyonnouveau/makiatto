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

    /// Image processing configuration
    #[serde(default)]
    pub images: ImageConfig,

    /// Observability configuration
    #[serde(default)]
    pub o11y: ObservabilityConfig,

    /// Consensus configuration
    #[serde(default)]
    pub consensus: ConsensusConfig,

    /// ACME configuration
    #[serde(default)]
    pub acme: AcmeConfig,

    /// File sync configuration
    #[serde(default)]
    pub fs: FileSyncConfig,
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
pub struct ImageConfig {
    /// Enable dynamic image processing
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum cache size in megabytes
    #[serde(default = "default_cache_size_mb")]
    pub cache_size_mb: usize,

    /// Maximum image width in pixels
    #[serde(default = "default_max_dimension")]
    pub max_width: u32,

    /// Maximum image height in pixels
    #[serde(default = "default_max_dimension")]
    pub max_height: u32,

    /// Allowed output formats
    #[serde(default = "default_allowed_formats")]
    pub allowed_formats: Vec<String>,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            cache_size_mb: default_cache_size_mb(),
            max_width: default_max_dimension(),
            max_height: default_max_dimension(),
            allowed_formats: default_allowed_formats(),
        }
    }
}

fn default_cache_size_mb() -> usize {
    500
}

fn default_max_dimension() -> u32 {
    4096
}

fn default_allowed_formats() -> Vec<String> {
    vec![
        "webp".to_string(),
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
    ]
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

fn default_false() -> bool {
    false
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
pub struct AcmeConfig {
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

    /// Hours after which to reset retry count for failed domains
    #[serde(default = "default_retry_reset_hours")]
    pub retry_reset_hours: u32,

    /// ACME account email
    #[serde(default)]
    pub email: String,

    /// ACME directory URL
    #[serde(default = "default_false")]
    pub staging: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            check_interval: default_check_interval(),
            renewal_threshold: default_renewal_threshold(),
            max_retry_attempts: default_max_retry_attempts(),
            retry_reset_hours: default_retry_reset_hours(),
            email: String::new(),
            staging: default_false(),
        }
    }
}

fn default_check_interval() -> u64 {
    300 // 5 minutes
}

fn default_renewal_threshold() -> u32 {
    30 // days
}

fn default_max_retry_attempts() -> u32 {
    5
}

fn default_retry_reset_hours() -> u32 {
    24 // hours
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileSyncConfig {
    /// Enable file synchronization
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Content storage directory
    #[serde(default = "default_storage_dir")]
    pub storage_dir: Arc<Utf8PathBuf>,

    /// File sync HTTP server address
    pub addr: Option<Arc<str>>,

    /// Filesystem reconciliation interval in hours
    #[serde(default = "default_reconcile_interval")]
    pub reconcile_interval: u64,
}

impl Default for FileSyncConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            storage_dir: default_storage_dir(),
            addr: None,
            reconcile_interval: default_reconcile_interval(),
        }
    }
}

fn default_storage_dir() -> Arc<Utf8PathBuf> {
    Arc::new(Utf8PathBuf::from("/var/makiatto/storage"))
}

fn default_reconcile_interval() -> u64 {
    1
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
        Utf8PathBuf::from("./tests/fixtures/makiatto.local.toml"),
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
