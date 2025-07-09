#![cfg(test)]
use std::net::TcpListener;

use miette::{IntoDiagnostic, Result};
use rand::Rng;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

pub mod ubuntu {
    use super::*;

    pub async fn base(ssh_port: u16) -> Result<ContainerAsync<GenericImage>> {
        let image = GenericImage::new("makiatto-test-ubuntu_base", "latest")
            .with_exposed_port(22.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_mapped_port(ssh_port, 22.tcp())
            .with_cap_add("NET_ADMIN");

        image.start().await.into_diagnostic()
    }
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
