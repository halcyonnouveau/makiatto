#![cfg(test)]
use std::{env, net::TcpListener, path, process::Command, sync::Arc};

use makiatto_cli::config::Machine;
use miette::{Result, miette};
use rand::{Rng, distr::Alphanumeric};
use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, ImageExt,
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
};

#[derive(Clone, PartialEq)]
pub enum Image {
    Base,
    Daemon,
}

pub struct ContainerContext {
    pub gateway_ip: Arc<str>,
    pub root: path::PathBuf,
    pub target: path::PathBuf,
    containers: Vec<TestContainer>,
}

impl ContainerContext {
    pub fn new() -> Result<Self> {
        let id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();

        let cwd = env::var("CARGO_MANIFEST_DIR").unwrap();
        let root = path::Path::new(&cwd).parent().unwrap();
        let target = root.join(format!("target/tests/context-{id}"));

        Self::ensure_wawa_network()?;

        Ok(Self {
            gateway_ip: Arc::from(Self::get_gateway_ip()?),
            root: root.to_owned(),
            target,
            containers: Vec::new(),
        })
    }

    fn ensure_wawa_network() -> Result<()> {
        let check_output = Command::new("docker")
            .args([
                "network",
                "ls",
                "--filter",
                "name=wawa",
                "--format",
                "{{.Name}}",
            ])
            .output()
            .map_err(|e| miette!("Failed to check for wawa network: {e}"))?;

        let networks = String::from_utf8_lossy(&check_output.stdout);
        if networks.trim() == "wawa" {
            return Ok(());
        }

        let create_output = Command::new("docker")
            .args(["network", "create", "wawa"])
            .output()
            .map_err(|e| miette!("Failed to create wawa network: {e}"))?;

        if !create_output.status.success() {
            let stderr = String::from_utf8_lossy(&create_output.stderr);
            if stderr.contains("already exists") {
                return Ok(());
            }
            return Err(miette!("Failed to create wawa network: {stderr}"));
        }

        Ok(())
    }

    fn get_gateway_ip() -> Result<String> {
        let output = Command::new("sh")
            .args([
                "-c",
                "docker network inspect wawa | grep -i gateway | head -1 | cut -f 4 -d '\"'",
            ])
            .output()
            .map_err(|e| miette::miette!("Failed to get wawa network gateway: {e}"))?;

        if !output.status.success() {
            return Err(miette::miette!("Failed to inspect wawa network"));
        }

        let gateway = String::from_utf8(output.stdout)
            .map_err(|e| miette::miette!("Invalid UTF-8 in gateway output: {e}"))?
            .trim()
            .to_string();

        if gateway.is_empty() {
            return Err(miette::miette!("No gateway found for wawa network"));
        }

        Ok(gateway)
    }

    pub async fn make_base(&mut self) -> Result<TestContainer> {
        let mut container = TestContainer::new(Image::Base)?;

        let image = GenericImage::new("makiatto-test-ubuntu_base", "latest")
            .with_exposed_port(22.tcp())
            .with_exposed_port(8787.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_container_name(format!("{}-wawa-base", container.id))
            .with_mapped_port(container.ports.ssh, 22.tcp())
            .with_mapped_port(container.ports.corrosion, 8787.tcp())
            .with_network("wawa");

        container.start_image(image).await?;
        self.containers.push(container.clone());

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        Ok(container)
    }

    pub async fn make_daemon(&mut self) -> Result<TestContainer> {
        let mut container = TestContainer::new(Image::Daemon)?;
        let target = self.target.join(format!("container-{}", container.id));

        tokio::fs::create_dir_all(&target)
            .await
            .map_err(|e| miette::miette!("Failed to create directory: {e}"))?;

        tokio::fs::copy(
            self.root.join("tests/fixtures/makiatto.toml"),
            target.join("makiatto.toml"),
        )
        .await
        .map_err(|e| miette::miette!("Failed to copy makiatto.toml: {e}"))?;

        Self::replace(
            "name = \"wawa-daemon\"",
            &format!("name = \"{}-wawa-daemon\"", container.id),
            &target.join("makiatto.toml"),
        )
        .await?;

        Self::replace(
            "external_addr = \"127.0.0.1:8787\"",
            &format!(
                "external_addr = \"{}:{}\"",
                self.gateway_ip, container.ports.corrosion
            ),
            &target.join("makiatto.toml"),
        )
        .await?;

        let prev_corro_ports: Vec<u16> = self
            .containers
            .iter()
            .filter_map(|c| {
                if c.image == Image::Daemon {
                    Some(c.ports.corrosion)
                } else {
                    None
                }
            })
            .collect();

        if !prev_corro_ports.is_empty() {
            let bootstrap: String = prev_corro_ports
                .iter()
                .map(|port| format!("\"{}:{port}\"", self.gateway_ip))
                .collect::<Vec<_>>()
                .join(", ");

            Self::replace(
                "bootstrap = []",
                &format!("bootstrap = [{bootstrap}]"),
                &target.join("makiatto.toml"),
            )
            .await?;
        }

        let image = GenericImage::new("makiatto-test-ubuntu_daemon", "latest")
            .with_exposed_port(22.tcp())
            .with_exposed_port(53.tcp())
            .with_exposed_port(53.udp())
            .with_exposed_port(80.tcp())
            .with_exposed_port(443.tcp())
            .with_exposed_port(8787.udp())
            .with_exposed_port(9090.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_container_name(format!("{}-wawa-daemon", container.id))
            .with_mapped_port(container.ports.ssh, 22.tcp())
            .with_mapped_port(container.ports.dns, 53.tcp())
            .with_mapped_port(container.ports.dns, 53.udp())
            .with_mapped_port(container.ports.http, 80.tcp())
            .with_mapped_port(container.ports.https, 443.tcp())
            .with_mapped_port(container.ports.corrosion, 8787.udp())
            .with_mapped_port(container.ports.metrics, 9090.tcp())
            .with_network("wawa")
            .with_mount(Mount::bind_mount(
                self.root.join("target/tests/geolite").display().to_string(),
                "/var/makiatto/geolite",
            ))
            .with_mount(Mount::bind_mount(
                target.display().to_string(),
                "/etc/makiatto",
            ));

        container.start_image(image).await?;
        self.containers.push(container.clone());

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        Ok(container)
    }

    /// replace a string in a file
    async fn replace(pattern: &str, replacement: &str, path: &path::Path) -> Result<()> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| miette::miette!("Failed to read file: {e}"))?;

        let new_content = content.replace(pattern, replacement);

        tokio::fs::write(path, new_content)
            .await
            .map_err(|e| miette::miette!("Failed to write file: {e}"))?;

        Ok(())
    }
}

impl Drop for ContainerContext {
    fn drop(&mut self) {
        if self.target.exists() {
            if let Err(e) = std::fs::remove_dir_all(&self.target) {
                eprintln!(
                    "Warning: Failed to clean up test data directory {}: {e}",
                    self.target.display(),
                );
            } else {
                eprintln!("Cleaned up test directory: {}", self.target.display());
            }
        }
    }
}

#[derive(Clone)]
pub struct TestContainer {
    pub id: Arc<str>,
    pub container: Option<Arc<ContainerAsync<GenericImage>>>,
    pub image: Image,
    pub ports: PortMap,
}

impl TestContainer {
    pub fn new(image: Image) -> Result<Self> {
        let id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();

        let ports = PortMap::new()?;

        Ok(Self {
            id: Arc::from(id),
            container: None,
            image,
            ports,
        })
    }

    pub async fn start_image(&mut self, image: ContainerRequest<GenericImage>) -> Result<()> {
        let container = Arc::from(
            image
                .start()
                .await
                .map_err(|e| miette!("Failed to start image: {e}"))?,
        );
        self.container = Some(container);
        Ok(())
    }

    pub fn get_config(&self) -> Machine {
        Machine {
            name: Arc::from(format!("{}-wawa-daemon", self.id)),
            ssh_target: Arc::from(format!("root@127.0.0.1:{}", self.ports.ssh)),
            is_nameserver: true,
            wg_public_key: Arc::from("todayiwantedtoeataquaso"),
            wg_address: Arc::from("0.0.0.0"),
            latitude: Some(69.1337),
            longitude: Some(69.1337),
            ipv4: Arc::from("127.0.0.1"),
            ipv6: None,
        }
    }
}

#[derive(Copy, Clone)]
pub struct PortMap {
    pub ssh: u16,
    pub dns: u16,
    pub corrosion: u16,
    pub http: u16,
    pub https: u16,
    pub metrics: u16,
}

impl PortMap {
    pub fn new() -> Result<Self> {
        for attempt in 1..=3 {
            match Self::try_allocate_ports() {
                Ok(ports) => return Ok(ports),
                Err(e) if attempt < 3 => {
                    eprintln!("Port allocation attempt {attempt} failed: {e}, retrying...");
                    std::thread::sleep(std::time::Duration::from_millis(100 * attempt));
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    fn try_allocate_ports() -> Result<Self> {
        let mut ports = std::collections::HashSet::new();
        let mut allocated = Vec::new();

        for _ in 0..6 {
            let mut attempts = 0;
            loop {
                let port = Self::get_unused_port()?;
                if !ports.contains(&port) {
                    ports.insert(port);
                    allocated.push(port);
                    break;
                }
                attempts += 1;
                if attempts > 50 {
                    return Err(miette::miette!(
                        "Failed to allocate unique ports after 50 attempts"
                    ));
                }
            }
        }

        Ok(Self {
            ssh: allocated[0],
            dns: allocated[1],
            corrosion: allocated[2],
            http: allocated[3],
            https: allocated[4],
            metrics: allocated[5],
        })
    }

    pub fn get_unused_port() -> Result<u16> {
        const MAX_ATTEMPTS: u32 = 100;

        let mut rng = rand::rng();
        let mut attempts = 0;

        while attempts < MAX_ATTEMPTS {
            let port = rng.random_range(32768..=65535);

            if TcpListener::bind(("127.0.0.1", port)).is_ok()
                && let Ok(socket) = std::net::UdpSocket::bind(("127.0.0.1", port))
            {
                drop(socket);
                return Ok(port);
            }
            attempts += 1;
        }

        Err(miette::miette!(
            "No unused ports available in range 32768-65535 after {} attempts",
            MAX_ATTEMPTS
        ))
    }
}
