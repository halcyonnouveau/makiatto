#![cfg(test)]
use std::{
    net::TcpListener,
    sync::{Arc, LazyLock},
};

use makiatto_cli::config::MachineConfig;
use miette::{IntoDiagnostic, Result};
use rand::Rng;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
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

pub struct TestContainer {
    pub container: ContainerAsync<GenericImage>,
    pub ports: PortMap,
}

pub mod ubuntu {
    use super::*;

    pub async fn base() -> Result<TestContainer> {
        let ports = PortMap::new()?;

        let image = GenericImage::new("makiatto-test-ubuntu_base", "latest")
            .with_exposed_port(22.tcp())
            .with_exposed_port(8787.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_mapped_port(ports.ssh, 22.tcp())
            .with_mapped_port(ports.corrosion, 8787.tcp());

        Ok(TestContainer {
            container: image.start().await.into_diagnostic()?,
            ports,
        })
    }

    pub async fn daemon0() -> Result<(TestContainer, MachineConfig)> {
        let ports = PortMap::new()?;

        let image = GenericImage::new("makiatto-test-ubuntu_daemon", "latest")
            .with_exposed_port(22.tcp())
            .with_exposed_port(8787.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_mapped_port(ports.ssh, 22.tcp())
            .with_mapped_port(ports.corrosion, 8787.tcp())
            .with_network("wawa");

        Ok((
            TestContainer {
                container: image.start().await.into_diagnostic()?,
                ports,
            },
            get_daemon_with_port(0, ports.ssh),
        ))
    }
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
