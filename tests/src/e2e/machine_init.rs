#![cfg(test)]
use std::time::Duration;

use makiatto_cli::{config::GlobalConfig, machine::InitMachine};
use miette::Result;

use crate::container::{ContainerContext, PortMap, TestContainer};

#[tokio::test]
async fn test_machine_init_first() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: _base_container,
        ports: PortMap { ssh, .. },
        ..
    } = context.make_base().await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let mut config = GlobalConfig { machines: vec![] };

    let request = InitMachine {
        name: "test-machine-init-first".into(),
        ssh_target: format!("root@localhost:{ssh}"),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(context.root.join("target/tests/makiatto")),
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    let ssh = makiatto_cli::machine::init_machine(&request, &mut config)?;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

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
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: _base_container,
        ports: PortMap { ssh, .. },
        ..
    } = context.make_base().await?;

    let daemon = context.make_daemon().await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let mut config = GlobalConfig {
        machines: vec![daemon.get_config()],
    };

    let request = InitMachine {
        name: "test-machine-init-second".into(),
        ssh_target: format!("root@localhost:{ssh}"),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(context.root.join("target/tests/makiatto")),
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    let ssh = makiatto_cli::machine::init_machine(&request, &mut config)?;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

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
