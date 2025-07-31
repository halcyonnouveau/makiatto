use std::collections::HashMap;
use std::sync::Arc;

use camino::Utf8PathBuf;
use miette::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct CacheStore {
    path: Utf8PathBuf,
    data: Arc<RwLock<CacheData>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheData {
    #[serde(default)]
    subscriptions: HashMap<String, SubscriptionState>,

    #[serde(default)]
    cache: HashMap<String, serde_json::Value>,

    #[serde(default)]
    version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionState {
    pub query_id: Option<String>,
    pub last_change_id: u64,
}

impl CacheStore {
    /// Create a new cache store
    ///
    /// # Errors
    /// Returns an error if the cache file exists but cannot be read or parsed
    pub fn new(data_dir: &Utf8PathBuf) -> Result<Self> {
        let path = data_dir.join("cache.json");
        let data = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<CacheData>(&content) {
                    Ok(data) => {
                        debug!("Loaded cache from {path}");
                        data
                    }
                    Err(e) => {
                        warn!("Failed to parse cache file, starting fresh: {e}");
                        CacheData::default()
                    }
                },
                Err(e) => {
                    warn!("Failed to read cache file, starting fresh: {e}");
                    CacheData::default()
                }
            }
        } else {
            debug!("No cache file found, starting fresh");
            CacheData::default()
        };

        Ok(Self {
            path,
            data: Arc::new(RwLock::new(data)),
        })
    }

    /// Get subscription state
    pub async fn get_subscription(&self, key: &str) -> Option<SubscriptionState> {
        let data = self.data.read().await;
        data.subscriptions.get(key).cloned()
    }

    /// Set subscription state
    pub async fn set_subscription(&self, key: &str, state: SubscriptionState) {
        let mut data = self.data.write().await;
        data.subscriptions.insert(key.to_string(), state);
    }

    /// Persist state to disk
    ///
    /// # Errors
    /// Returns an error if the cache cannot be persisted to disk
    pub async fn persist(&self) -> Result<()> {
        let data = self.data.read().await;
        let content = serde_json::to_string_pretty(&*data)
            .map_err(|e| miette::miette!("Failed to serialize cache data: {e}"))?;

        // Write to temporary file first for atomicity
        let temp_path = format!("{}.tmp", self.path);
        tokio::fs::write(&temp_path, content)
            .await
            .map_err(|e| miette::miette!("Failed to write cache file to {temp_path}: {e}"))?;

        // Rename to final location (atomic on most filesystems)
        tokio::fs::rename(&temp_path, &self.path)
            .await
            .map_err(|e| {
                miette::miette!(
                    "Failed to rename cache file from {temp_path} to {}: {e}",
                    self.path
                )
            })?;

        debug!("Persisted cache to {}", self.path);
        Ok(())
    }
}
