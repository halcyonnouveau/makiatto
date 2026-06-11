#![cfg(test)]
use miette::{IntoDiagnostic, Result};

use crate::container::{ContainerContext, PortMap, TestContainer};

/// Corrupt the key blob of each `known_hosts` line so the stored key no longer
/// matches the server's real host key, while keeping each entry well-formed
/// (same field layout, same base64 length).
fn corrupt_known_hosts(content: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.splitn(3, ' ').collect();
        if fields.len() == 3 {
            let mut blob: Vec<char> = fields[2].chars().collect();
            // flip a character in the middle of the base64 key material: changes
            // the decoded bytes without disturbing the type framing or padding
            let idx = blob.len() / 2;
            blob[idx] = if blob[idx] == 'A' { 'B' } else { 'A' };
            let blob: String = blob.into_iter().collect();
            lines.push(format!("{} {} {}", fields[0], fields[1], blob));
        } else {
            lines.push(line.to_string());
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// A connection whose recorded host key no longer matches the server's key must
/// be rejected (potential machine-in-the-middle), rather than silently trusted.
#[tokio::test]
async fn test_ssh_host_key_mismatch_is_rejected() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        ports: PortMap { ssh, .. },
        ..
    } = context.make_base().await?;

    // isolate known_hosts to a temp file for this test
    let kh_dir = std::env::temp_dir().join(format!("maki-kh-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&kh_dir).into_diagnostic()?;
    let kh_path = kh_dir.join("known_hosts");
    // SAFETY: nextest runs each test in its own process, so mutating the
    // environment here does not race other tests.
    unsafe { std::env::set_var("MAKIATTO_KNOWN_HOSTS", &kh_path) };

    let key = context.root.join("tests/fixtures/.ssh/id_ed25519");

    // first connect records the host key (trust on first use)
    makiatto_cli::ssh::SshSession::new("root@localhost", Some(ssh), Some(&key))?;

    let recorded = std::fs::read_to_string(&kh_path).into_diagnostic()?;
    assert!(
        !recorded.trim().is_empty(),
        "TOFU did not record a host key on first connect"
    );

    // tamper with the stored key, then reconnect — must be rejected
    std::fs::write(&kh_path, corrupt_known_hosts(&recorded)).into_diagnostic()?;

    let result = makiatto_cli::ssh::SshSession::new("root@localhost", Some(ssh), Some(&key));

    // SAFETY: see above.
    unsafe { std::env::remove_var("MAKIATTO_KNOWN_HOSTS") };
    std::fs::remove_dir_all(&kh_dir).ok();

    assert!(
        result.is_err(),
        "expected a changed host key to be rejected, but the connection succeeded"
    );

    Ok(())
}
