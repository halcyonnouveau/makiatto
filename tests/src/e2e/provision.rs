#![cfg(test)]
use makiatto_cli::{config::Profile, machine::InitMachine};
use miette::{IntoDiagnostic, Result, miette};
use testcontainers::core::ExecCommand;

use crate::container::{ContainerContext, PortMap, TestContainer};

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
        ssh_target: format!("root@localhost:{ssh}"),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(context.root.join("target/tests/makiatto")),
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    makiatto_cli::machine::init_machine(&request, &mut config).await?;
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
        ssh_target: format!("root@localhost:{ssh}"),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(context.root.join("target/tests/makiatto")),
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    makiatto_cli::machine::init_machine(&request, &mut config).await?;

    // test peer data replicated to daemon container
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let mut query = daemon
        .container
        .expect("No daemon container")
        .exec(ExecCommand::new(vec![
            "sqlite3",
            "/var/makiatto/cluster.db",
            "SELECT name, wg_public_key, ipv4 FROM peers WHERE name = 'test-machine-init-second';",
        ]))
        .await
        .map_err(|e| miette!("Failed to query d1: {e}"))?;

    let d1_stdout = query.stdout_to_vec().await.into_diagnostic()?;
    let stdout = String::from_utf8_lossy(&d1_stdout);

    assert!(!stdout.is_empty(), "No data returned from d1 query");
    assert!(stdout.contains("test-machine-init-second"));

    Ok(())
}
