#![cfg(test)]
use std::{env, path::PathBuf, time::Duration};

use makiatto_cli::{config::GlobalConfig, machine::InitMachine};
use miette::Result;

use crate::container::{self, get_unused_port};

#[tokio::test]
async fn test_machine_init_first() -> Result<()> {
    let ssh_port = get_unused_port()?;
    let _container = container::ubuntu::base(ssh_port).await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    let mut config = GlobalConfig { machines: vec![] };

    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();

    let request = InitMachine {
        name: "test-machine-init-first".into(),
        ssh_target: format!("root@localhost:{ssh_port}").into(),
        skip_nameserver: false,
        force_nameserver: false,
        override_existing: false,
        binary_path: Some(workspace_root.join("target/tests/makiatto")),
        key_path: Some(workspace_root.join("tests/.ssh/id_ed25519")),
        install_only: true,
    };

    let ssh = makiatto_cli::machine::init_machine(request, &mut config).await?;

    // if it runs for N seconds, everything *probably* should have started
    let response = ssh.exec_timeout("/usr/local/bin/makiatto", Duration::from_secs(3));
    assert!(response.is_err_and(|err| { err.to_string().contains("Timed out waiting on socket") }));

    Ok(())
}
