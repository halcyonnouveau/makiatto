use std::path::PathBuf;

use miette::{Result, miette};
use serde::{Deserialize, Serialize};

/// Global configuration stored in ~/.config/makiatto/default.toml
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    pub machines: Vec<MachineConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MachineConfig {
    pub name: String,
    pub ssh_target: String,
    pub is_nameserver: bool,
    pub wg_public_key: String,
    pub wg_address: String,
    pub wg_endpoint: String,
}

/// Local project configuration stored in ./makiatto.toml
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalConfig {
    pub domain: String,
    /// CNAME records to the canonical domain
    pub aliases: Vec<String>,
    pub paths: Vec<PathBuf>,
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub value: String,
}

impl GlobalConfig {
    pub fn load(custom_path: Option<impl Into<PathBuf>>) -> Result<Self> {
        let config_path = match custom_path {
            Some(path) => path.into(),
            None => Self::default_path()?,
        };

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| miette!("Failed to read config: {}", e))?;

        toml::from_str(&content).map_err(|e| miette!("Failed to parse config: {}", e))
    }

    pub fn add_machine(&mut self, machine: MachineConfig) {
        if let Some(existing) = self.machines.iter_mut().find(|m| m.name == machine.name) {
            *existing = machine;
        } else {
            self.machines.push(machine);
        }
    }

    pub fn remove_machine(&mut self, name: &str) -> bool {
        let original_len = self.machines.len();
        self.machines.retain(|m| m.name != name);
        self.machines.len() != original_len
    }

    #[must_use] pub fn find_machine(&self, name: &str) -> Option<&MachineConfig> {
        self.machines.iter().find(|m| m.name == name)
    }

    pub fn save(&self, custom_path: Option<impl Into<PathBuf>>) -> Result<()> {
        let config_path = match custom_path {
            Some(path) => path.into(),
            None => Self::default_path()?,
        };

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette!("Failed to create config directory: {}", e))?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| miette!("Failed to serialize config: {}", e))?;

        std::fs::write(&config_path, content).map_err(|e| miette!("Failed to write config: {}", e))
    }

    fn default_path() -> Result<PathBuf> {
        let home = dirs::config_dir().ok_or_else(|| miette!("Could not find config directory"))?;
        Ok(home.join("makiatto/default.toml"))
    }
}

impl LocalConfig {
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
            .map_err(|e| miette!("Failed to read local config: {}", e))?;

        toml::from_str(&content).map_err(|e| miette!("Failed to parse local config: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_config_machine_management() {
        let mut config = GlobalConfig::default();

        let machine1 = MachineConfig {
            name: "test1".to_string(),
            ssh_target: "user@host1".to_string(),
            is_nameserver: false,
            wg_public_key: "key1".to_string(),
            wg_address: "10.0.0.1".to_string(),
            wg_endpoint: "host1:51820".to_string(),
        };

        let machine2 = MachineConfig {
            name: "test2".to_string(),
            ssh_target: "user@host2".to_string(),
            is_nameserver: true,
            wg_public_key: "key2".to_string(),
            wg_address: "10.0.0.2".to_string(),
            wg_endpoint: "host2:51820".to_string(),
        };

        config.add_machine(machine1.clone());
        config.add_machine(machine2.clone());
        assert_eq!(config.machines.len(), 2);

        assert!(config.find_machine("test1").is_some());
        assert!(config.find_machine("nonexistent").is_none());

        assert!(config.remove_machine("test1"));
        assert_eq!(config.machines.len(), 1);
        assert!(!config.remove_machine("nonexistent"));

        let updated_machine = MachineConfig {
            name: "test2".to_string(),
            ssh_target: "newuser@newhost".to_string(),
            ..machine2
        };

        config.add_machine(updated_machine);
        assert_eq!(config.machines.len(), 1);
        assert_eq!(
            config.find_machine("test2").unwrap().ssh_target,
            "newuser@newhost"
        );
    }
}
