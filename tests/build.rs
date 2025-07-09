#![allow(unused_imports)]
use std::{env, process::Command};

use miette::{IntoDiagnostic, Result, bail};

#[cfg(feature = "docker-build")]
fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=dockerfiles");

    let cwd = env::var("CARGO_MANIFEST_DIR").into_diagnostic()?;
    let workspace_root = std::path::Path::new(&cwd).parent().unwrap();

    let dockerfiles = vec![
        (
            "makiatto_builder",
            "makiatto-builder",
            Some(format!("type=local,dest={cwd}/../target/tests")),
        ),
        ("ubuntu_base", "makiatto-test-ubuntu_base", None),
        ("ubuntu_daemon", "makiatto-test-ubuntu_daemon", None),
    ];

    for (dockerfile, tag, export) in dockerfiles {
        eprintln!("Building {tag}...");

        let mut docker = Command::new("docker");

        docker
            .arg("build")
            .arg("--file")
            .arg(format!("{cwd}/dockerfiles/{dockerfile}.Dockerfile"))
            .arg("--force-rm")
            .arg("--tag")
            .arg(format!("{tag}:latest"));

        if let Some(export) = export {
            docker.arg("--output").arg(export);
        }

        let output = docker.arg(workspace_root).output().into_diagnostic()?;

        if !output.status.success() {
            eprintln!(
                "stderr: {}",
                String::from_utf8(output.stderr).into_diagnostic()?
            );
            bail!(format!("unable to build {tag}:latest"));
        }

        eprintln!("Successfully built {tag}:latest");
    }

    Ok(())
}

#[cfg(not(feature = "docker-build"))]
fn main() {}
