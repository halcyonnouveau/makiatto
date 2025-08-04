#![cfg(test)]
use makiatto_cli::{config::Profile, machine::InitMachine};
use miette::Result;

use crate::container::{ContainerContext, PortMap, TestContainer, util};

#[tokio::test]
async fn test_provision_first() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: _base_container,
        ports: PortMap { ssh, .. },
        ..
    } = context.make_base().await?;

    let mut config = Profile { machines: vec![] };

    let request = InitMachine {
        name: "test-machine-init-first".into(),
        ssh_target: "root@localhost".into(),
        port: Some(ssh),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(context.root.join("target/tests/makiatto")),
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    makiatto_cli::machine::init_machine(&request, &mut config)?;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}

#[tokio::test]
async fn test_provision_second() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: _base_container,
        ports: PortMap { ssh, .. },
        ..
    } = context.make_base().await?;

    let daemon = context.make_daemon().await?;

    let mut config = Profile {
        machines: vec![daemon.get_config()],
    };

    let request = InitMachine {
        name: "test-machine-init-second".into(),
        ssh_target: "root@localhost".into(),
        port: Some(ssh),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(context.root.join("target/tests/makiatto")),
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    makiatto_cli::machine::init_machine(&request, &mut config)?;

    // test peer data replicated to daemon container
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let stdout = util::query_database(
        daemon.container.as_ref().expect("No daemon container"),
        "SELECT name, wg_public_key, ipv4 FROM peers WHERE name = 'test-machine-init-second';",
    )
    .await?;

    assert!(!stdout.is_empty(), "No data returned from d1 query");
    assert!(stdout.contains("test-machine-init-second"));

    Ok(())
}
