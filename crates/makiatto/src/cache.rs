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
    ///
    /// # Errors
    /// Returns an error if the cache cannot be persisted to disk
    pub async fn set_subscription(&self, key: &str, state: SubscriptionState) -> Result<()> {
        {
            let mut data = self.data.write().await;
            data.subscriptions.insert(key.to_string(), state);
        }
        self.persist().await
    }

    /// Get cached value
    pub async fn get_cache(&self, key: &str) -> Option<serde_json::Value> {
        let data = self.data.read().await;
        data.cache.get(key).cloned()
    }

    /// Set cached value
    ///
    /// # Errors
    /// Returns an error if the cache cannot be persisted to disk
    pub async fn set_cache(&self, key: &str, value: serde_json::Value) -> Result<()> {
        {
            let mut data = self.data.write().await;
            data.cache.insert(key.to_string(), value);
        }
        self.persist().await
    }

    /// Remove cached value
    ///
    /// # Errors
    /// Returns an error if the cache cannot be persisted to disk
    pub async fn remove_cache(&self, key: &str) -> Result<()> {
        {
            let mut data = self.data.write().await;
            data.cache.remove(key);
        }
        self.persist().await
    }

    /// Clear all cached values
    ///
    /// # Errors
    /// Returns an error if the cache cannot be persisted to disk
    pub async fn clear_cache(&self) -> Result<()> {
        {
            let mut data = self.data.write().await;
            data.cache.clear();
        }
        self.persist().await
    }

    /// Persist state to disk
    async fn persist(&self) -> Result<()> {
        let data = self.data.read().await;
        let content = serde_json::to_string_pretty(&*data)
            .map_err(|e| miette::miette!("Failed to serialize cache data: {e}"))?;

        // Write to temporary file first for atomicity
        let temp_path = format!("{}.tmp", self.path);
        tokio::fs::write(&temp_path, content)
            .await
            .map_err(|e| miette::miette!("Failed to write cache file: {e}"))?;

        // Rename to final location (atomic on most filesystems)
        tokio::fs::rename(&temp_path, &self.path)
            .await
            .map_err(|e| miette::miette!("Failed to rename cache file: {e}"))?;

        debug!("Persisted cache to {}", self.path);
        Ok(())
    }

    /// Force reload from disk
    ///
    /// # Errors
    /// Returns an error if the cache file cannot be read or parsed
    pub async fn reload(&self) -> Result<()> {
        if self.path.exists() {
            let content = tokio::fs::read_to_string(&self.path)
                .await
                .map_err(|e| miette::miette!("Failed to read cache file: {e}"))?;
            let new_data = serde_json::from_str::<CacheData>(&content)
                .map_err(|e| miette::miette!("Failed to parse cache file: {e}"))?;

            let mut data = self.data.write().await;
            *data = new_data;

            debug!("Reloaded cache from {}", self.path);
        }
        Ok(())
    }
}
