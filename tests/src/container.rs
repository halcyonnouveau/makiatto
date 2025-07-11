#![cfg(test)]
use std::{
    env,
    net::TcpListener,
    path,
    process::Command,
    sync::{Arc, LazyLock},
};

use makiatto_cli::config::MachineConfig;
use miette::{IntoDiagnostic, Result};
use rand::{Rng, distr::Alphanumeric};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
};

// make sure to edit build.rs as well
static DAEMON_MACHINE_CONFIGS: LazyLock<Vec<MachineConfig>> = LazyLock::new(|| {
    vec![MachineConfig {
        name: Arc::from("daemon0"),
        ssh_target: Arc::from("root@127.0.0.1"),
        is_nameserver: true,
        wg_public_key: Arc::from("todayiwantedtoeataquaso"),
        wg_address: Arc::from("0.0.0.0"),
        latitude: Some(45.5186),
        longitude: Some(69.1337),
        ipv4: Arc::from("127.0.0.1"),
        ipv6: None,
    }]
});

fn get_daemon_with_port(index: usize, ssh_port: u16) -> MachineConfig {
    let mut config = DAEMON_MACHINE_CONFIGS.get(index).unwrap().to_owned();
    config.ssh_target = Arc::from(format!("root@127.0.0.1:{ssh_port}"));
    config
}

pub struct ContainerContext {
    id: Arc<str>,
    root: path::PathBuf,
    target: path::PathBuf,
    containers: Vec<TestContainer>,
}

impl ContainerContext {
    pub fn new() -> Self {
        let id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();

        let cwd = env::var("CARGO_MANIFEST_DIR").unwrap();
        let root = path::Path::new(&cwd).parent().unwrap();
        let target = root.join(format!("target/tests/{id}"));

        Self {
            id: Arc::from(id),
            root: root.to_owned(),
            target,
            containers: Vec::new(),
        }
    }

    pub async fn make_base(&mut self) -> Result<TestContainer> {
        let ports = PortMap::new()?;

        let image = GenericImage::new("makiatto-test-ubuntu_base", "latest")
            .with_exposed_port(22.tcp())
            .with_exposed_port(8787.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_container_name(format!("{}-wawa-base", self.id))
            .with_mapped_port(ports.ssh, 22.tcp())
            .with_mapped_port(ports.corrosion, 8787.tcp())
            .with_network(self.id.to_string());

        let container = TestContainer {
            container: Arc::from(image.start().await.into_diagnostic()?),
            ports,
        };

        self.containers.push(container.clone());

        Ok(container)
    }

    pub async fn make_daemon(&mut self) -> Result<(TestContainer, MachineConfig)> {
        Command::new("mkdir")
            .arg("-p")
            .arg(&self.target)
            .status()
            .map_err(|e| miette::miette!("Failed to create directory: {e}"))?;

        Command::new("cp")
            .arg(self.root.join("tests/fixtures/makiatto.toml"))
            .arg(self.target.join("makiatto.toml"))
            .status()
            .map_err(|e| miette::miette!("Failed to copy makiatto.toml: {e}"))?;

        self.config_replace(
            "name = \"wawa-daemon\"",
            &format!("name = \"{}-wawa-daemon\"", self.id),
        )?;

        let ports = PortMap::new()?;

        let image = GenericImage::new("makiatto-test-ubuntu_daemon", "latest")
            .with_exposed_port(22.tcp())
            .with_exposed_port(8787.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_container_name(format!("{}-wawa-daemon", self.id))
            .with_mapped_port(ports.ssh, 22.tcp())
            .with_mapped_port(ports.corrosion, 8787.tcp())
            .with_network(self.id.to_string())
            .with_mount(Mount::bind_mount(
                self.target.display().to_string(),
                "/etc/makiatto",
            ));

        let container = TestContainer {
            container: Arc::from(image.start().await.into_diagnostic()?),
            ports,
        };

        self.containers.push(container.clone());

        Ok((container, get_daemon_with_port(0, ports.ssh)))
    }

    /// Run sed command on test context config
    fn config_replace(&self, pattern: &str, replacement: &str) -> Result<()> {
        let file_path = self.target.join("makiatto.toml");
        let status = if cfg!(target_os = "macos") {
            Command::new("sed")
                .args([
                    "-i",
                    "",
                    &format!("s/{pattern}/{replacement}/"),
                    &file_path.display().to_string(),
                ])
                .status()
        } else {
            Command::new("sed")
                .args([
                    "-i",
                    &format!("s/{pattern}/{replacement}/"),
                    &file_path.display().to_string(),
                ])
                .status()
        };

        status
            .map_err(|e| miette::miette!("Failed to run sed: {}", e))
            .and_then(|s| {
                if s.success() {
                    Ok(())
                } else {
                    Err(miette::miette!("sed command failed with status: {}", s))
                }
            })
    }
}

impl Drop for ContainerContext {
    fn drop(&mut self) {
        if self.target.exists() {
            if let Err(e) = std::fs::remove_dir_all(&self.target) {
                eprintln!(
                    "Warning: Failed to clean up test directory {}: {}",
                    self.target.display(),
                    e
                );
            } else {
                eprintln!("Cleaned up test directory: {}", self.target.display());
            }
        }
    }
}

#[derive(Clone)]
pub struct TestContainer {
    pub container: Arc<ContainerAsync<GenericImage>>,
    pub ports: PortMap,
}

#[derive(Copy, Clone)]
pub struct PortMap {
    pub ssh: u16,
    pub corrosion: u16,
}

impl PortMap {
    pub fn new() -> Result<Self> {
        Ok(Self {
            ssh: Self::get_unused_port()?,
            corrosion: Self::get_unused_port()?,
        })
    }

    pub fn get_unused_port() -> Result<u16> {
        const MAX_ATTEMPTS: u32 = 1000;

        let mut rng = rand::rng();
        let mut attempts = 0;

        while attempts < MAX_ATTEMPTS {
            let port = rng.random_range(49152..=65535);
            if TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return Ok(port);
            }
            attempts += 1;
        }

        Err(miette::miette!(
            "No unused ports available in range 49152-65535 after {} attempts",
            MAX_ATTEMPTS
        ))
    }
}
