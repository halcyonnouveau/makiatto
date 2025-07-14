#![allow(unused_imports)]
use std::{env, process::Command};

use miette::{IntoDiagnostic, Result, bail};

fn main() -> Result<()> {
    let cwd = env::var("CARGO_MANIFEST_DIR").into_diagnostic()?;
    let workspace_root = std::path::Path::new(&cwd).parent().unwrap();

    #[cfg(feature = "docker-build")]
    {
        println!("cargo:rerun-if-changed=dockerfiles");
        println!("cargo:rerun-if-changed=../crates/makiatto");

        let dockerfiles = vec![
            ("makiatto_builder", "makiatto-builder"),
            ("ubuntu_base", "makiatto-test-ubuntu_base"),
            ("ubuntu_daemon", "makiatto-test-ubuntu_daemon"),
        ];

        for (dockerfile, tag) in dockerfiles {
            eprintln!("Building {tag}...");

            let mut docker = Command::new("docker");

            let output = docker
                .arg("build")
                .arg("--file")
                .arg(format!("{cwd}/dockerfiles/{dockerfile}.Dockerfile"))
                .arg("--force-rm")
                .arg("--tag")
                .arg(format!("{tag}:latest"))
                .arg(workspace_root)
                .output()
                .into_diagnostic()?;

            if !output.status.success() {
                eprintln!(
                    "stderr: {}",
                    String::from_utf8(output.stderr).into_diagnostic()?
                );
                bail!(format!("unable to build {tag}:latest"));
            }

            eprintln!("Successfully built {tag}:latest");
        }
    }

    // always export makiatto binary from builder (silently fail if not available)
    let _ = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{cwd}/../target/tests:/output"),
            "makiatto-builder:latest",
            "sh",
            "-c",
            "cp /makiatto /output/",
        ])
        .output();

    let geolite_dir = workspace_root.join("target/tests/geolite");
    let geolite_file = geolite_dir.join("GeoLite2-City.mmdb");

    std::fs::create_dir_all(&geolite_dir).into_diagnostic()?;

    if !geolite_file.exists() {
        eprintln!("Downloading GeoLite2 database...");

        let _ = Command::new("curl")
            .args([
                "-s",
                "-L",
                "-o",
                &geolite_file.to_string_lossy(),
                "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
            ])
            .output();
    }
    Ok(())
}
