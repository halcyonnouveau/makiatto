#![cfg(test)]
use std::{env, path::PathBuf, time::Duration};

use makiatto_cli::{config::GlobalConfig, machine::InitMachine};
use miette::Result;

use crate::container::{self, PortMap, TestContainer};

#[tokio::test]
async fn test_machine_init_first() -> Result<()> {
    let TestContainer {
        container: _base_container,
        ports: PortMap { ssh, .. },
    } = container::ubuntu::base().await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let mut config = GlobalConfig { machines: vec![] };

    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();

    let request = InitMachine {
        name: "test-machine-init-first".into(),
        ssh_target: format!("root@localhost:{ssh}"),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(workspace_root.join("target/tests/makiatto")),
        key_path: Some(workspace_root.join("tests/.ssh/id_ed25519")),
    };

    let ssh = makiatto_cli::machine::init_machine(&request, &mut config)?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // if it runs for N seconds, everything *probably* should have started
    let response = ssh.exec_timeout(
        "sudo -u makiatto /usr/local/bin/makiatto",
        Duration::from_secs(2),
    );

    if let Ok(output) = &response {
        println!("Unexpected success: {output}");
    }

    assert!(response.is_err_and(|err| { err.to_string().contains("Timed out waiting on socket") }));

    Ok(())
}

#[tokio::test]
async fn test_machine_init_second() -> Result<()> {
    let TestContainer {
        container: _base_container,
        ports: PortMap { ssh, .. },
        ..
    } = container::ubuntu::base().await?;

    let (
        TestContainer {
            container: _daemon_container,
            ..
        },
        daemon_config,
    ) = container::ubuntu::daemon0().await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let mut config = GlobalConfig {
        machines: vec![daemon_config],
    };

    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();

    let request = InitMachine {
        name: "test-machine-init-second".into(),
        ssh_target: format!("root@localhost:{ssh}"),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(workspace_root.join("target/tests/makiatto")),
        key_path: Some(workspace_root.join("tests/.ssh/id_ed25519")),
    };

    let ssh = makiatto_cli::machine::init_machine(&request, &mut config)?;

    let response = ssh.exec_timeout(
        "sudo -u makiatto /usr/local/bin/makiatto",
        Duration::from_secs(2),
    );

    if let Ok(output) = &response {
        println!("Unexpected success: {output}");
    }

    assert!(response.is_err_and(|err| { err.to_string().contains("Timed out waiting on socket") }));

    Ok(())
}
