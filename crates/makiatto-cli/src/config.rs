use std::{collections::HashMap, path::PathBuf, sync::Arc};

use miette::{Result, miette};
use serde::{Deserialize, Serialize};

/// Profile configuration stored in ~/.config/makiatto/default.toml
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Profile {
    pub machines: Vec<Machine>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Machine {
    pub name: Arc<str>,
    pub ssh_target: Arc<str>,
    pub port: Option<u16>,
    pub is_nameserver: bool,
    pub wg_public_key: Arc<str>,
    pub wg_address: Arc<str>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub ipv4: Arc<str>,
    pub ipv6: Option<Arc<str>>,
    pub sync_target: bool,
}

/// Project configuration stored in ./makiatto.toml
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "domain")]
    pub domains: Arc<[Domain]>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Domain {
    pub name: Arc<str>,
    pub path: PathBuf,
    /// CNAME records to the canonical domain
    #[serde(default)]
    pub aliases: Arc<[Arc<str>]>,
    #[serde(default)]
    pub records: Arc<[DnsRecord]>,
    #[serde(default)]
    pub functions: Arc<[WasmFunction]>,
    #[serde(default)]
    pub transforms: Arc<[WasmTransform]>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: Arc<str>,
    #[serde(default = "default_record_name")]
    pub name: Arc<str>,
    pub value: Arc<str>,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub priority: Option<i32>,
}

fn default_record_name() -> Arc<str> {
    "@".into()
}

fn default_ttl() -> u32 {
    300
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WasmFunction {
    pub path: PathBuf,
    #[serde(default)]
    pub methods: Option<Arc<[Arc<str>]>>,
    #[serde(default)]
    pub env_file: Option<PathBuf>,
    #[serde(default)]
    pub env: HashMap<Arc<str>, Arc<str>>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub max_memory_mb: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WasmTransform {
    pub path: PathBuf,
    pub files: Arc<str>, // glob pattern
    #[serde(default)]
    pub env_file: Option<PathBuf>,
    #[serde(default)]
    pub env: HashMap<Arc<str>, Arc<str>>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub max_memory_mb: Option<u64>,
    #[serde(default)]
    pub max_file_size_kb: Option<u64>,
}

impl Profile {
    /// Load profile from file
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed
    pub fn load(custom_path: Option<impl Into<PathBuf>>) -> Result<Self> {
        let config_path = match custom_path {
            Some(path) => path.into(),
            None => {
                if let Ok(env_path) = std::env::var("MAKIATTO_PROFILE") {
                    PathBuf::from(env_path)
                } else {
                    Self::default_path()?
                }
            }
        };

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| miette!("Failed to read config: {e}"))?;

        toml::from_str(&content).map_err(|e| miette!("Failed to parse config: {e}"))
    }

    pub fn add_machine(&mut self, machine: Machine) {
        if let Some(existing) = self.machines.iter_mut().find(|m| m.name == machine.name) {
            *existing = machine;
        } else {
            self.machines.push(machine);
        }
    }

    pub fn remove_machine(&mut self, name: &str) -> bool {
        let original_len = self.machines.len();
        self.machines.retain(|m| m.name != name.into());
        self.machines.len() != original_len
    }

    #[must_use]
    pub fn find_machine(&self, name: &str) -> Option<&Machine> {
        self.machines.iter().find(|m| m.name == name.into())
    }

    /// Save profile to file
    ///
    /// # Errors
    /// Returns an error if the file cannot be written
    pub fn save(&self, custom_path: Option<impl Into<PathBuf>>) -> Result<()> {
        let config_path = match custom_path {
            Some(path) => path.into(),
            None => {
                if let Ok(env_path) = std::env::var("MAKIATTO_PROFILE") {
                    PathBuf::from(env_path)
                } else {
                    Self::default_path()?
                }
            }
        };

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette!("Failed to create config directory: {e}"))?;
        }

        let content =
            toml::to_string_pretty(self).map_err(|e| miette!("Failed to serialize config: {e}"))?;

        std::fs::write(&config_path, content).map_err(|e| miette!("Failed to write config: {e}"))
    }

    fn default_path() -> Result<PathBuf> {
        let base_dir = if cfg!(unix) {
            dirs::home_dir()
                .ok_or_else(|| miette!("Could not find home directory"))?
                .join(".config")
        } else {
            dirs::config_dir().ok_or_else(|| miette!("Could not find config directory"))?
        };

        Ok(base_dir.join("makiatto/default.toml"))
    }
}

impl Config {
    /// Load project configuration from file
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed
    pub fn load(custom_path: Option<impl Into<PathBuf>>) -> Result<Self> {
        let config_path = match custom_path {
            Some(path) => path.into(),
            None => PathBuf::from("./makiatto.toml"),
        };

        if !config_path.exists() {
            return Err(miette!(
                "No makiatto.toml found at '{}'",
                config_path.display()
            ));
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| miette!("Failed to read local config: {e}"))?;

        toml::from_str(&content).map_err(|e| miette!("Failed to parse local config: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machines_config_machine_management() {
        let mut config = Profile::default();

        let machine1 = Machine {
            name: Arc::from("test1"),
            ssh_target: Arc::from("user@host1"),
            port: None,
            is_nameserver: false,
            wg_public_key: Arc::from("key1"),
            wg_address: Arc::from("10.0.0.1"),
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
            ipv4: Arc::from("1.2.3.4"),
            ipv6: Some(Arc::from("2001:db8::1")),
            sync_target: true,
        };

        let machine2 = Machine {
            name: Arc::from("test2"),
            ssh_target: Arc::from("user@host2"),
            port: Some(22),
            is_nameserver: true,
            wg_public_key: Arc::from("key2"),
            wg_address: Arc::from("10.0.0.2"),
            latitude: Some(51.5074),
            longitude: Some(-0.1278),
            ipv4: Arc::from("5.6.7.8"),
            ipv6: None,
            sync_target: false,
        };

        config.add_machine(machine1.clone());
        config.add_machine(machine2.clone());
        assert_eq!(config.machines.len(), 2);

        assert!(config.find_machine("test1").is_some());
        assert!(config.find_machine("nonexistent").is_none());

        assert!(config.remove_machine("test1"));
        assert_eq!(config.machines.len(), 1);
        assert!(!config.remove_machine("nonexistent"));

        let updated_machine = Machine {
            name: Arc::from("test2"),
            ssh_target: Arc::from("newuser@newhost"),
            ..machine2
        };

        config.add_machine(updated_machine);
        assert_eq!(config.machines.len(), 1);
        assert_eq!(
            config.find_machine("test2").unwrap().ssh_target,
            Arc::from("newuser@newhost")
        );
    }
}
