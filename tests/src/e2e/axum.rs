#![cfg(test)]
use std::sync::Arc;

use base64::prelude::*;
use miette::{IntoDiagnostic, Result, miette};
use testcontainers::{
    GenericImage,
    core::{ContainerAsync, ExecCommand},
};

use crate::container::{ContainerContext, TestContainer};

#[tokio::test]
async fn test_virtual_hosting() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let commands = vec![
        "sudo mkdir -p /var/makiatto/sites/example.com",
        "echo '<h1>Example.com Homepage</h1>' | sudo tee /var/makiatto/sites/example.com/index.html",
    ];

    execute_commands(&daemon, &commands).await?;

    let example_com_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "example.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(example_com_response.status(), 200);
    let example_body = example_com_response.text().await.into_diagnostic()?;
    assert!(example_body.contains("Example.com Homepage"));

    Ok(())
}

#[tokio::test]
async fn test_static_file_serving() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let commands = vec![
        "sudo mkdir -p /var/makiatto/sites/localhost/assets",
        "echo '<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Test Page</h1></body></html>' | sudo tee /var/makiatto/sites/localhost/index.html",
        "echo 'body { color: red; }' | sudo tee /var/makiatto/sites/localhost/assets/style.css",
        "echo 'console.log(\"Hello world\");' | sudo tee /var/makiatto/sites/localhost/assets/script.js",
        "echo 'Plain text file content' | sudo tee /var/makiatto/sites/localhost/readme.txt",
        "sudo chown -R makiatto:makiatto /var/makiatto/sites",
    ];

    execute_commands(&daemon, &commands).await?;

    let html_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(html_response.status(), 200);
    let content_type = html_response.headers().get("content-type");
    assert!(content_type.is_some());
    let content_type_str = content_type.unwrap().to_str().into_diagnostic()?;
    assert!(content_type_str.contains("text/html"));

    let html_body = html_response.text().await.into_diagnostic()?;
    assert!(html_body.contains("Test Page"));

    let css_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/assets/style.css", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(css_response.status(), 200);
    let css_content_type = css_response.headers().get("content-type");
    assert!(css_content_type.is_some());
    let css_content_type_str = css_content_type.unwrap().to_str().into_diagnostic()?;
    assert!(css_content_type_str.contains("text/css"));

    let js_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/assets/script.js", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(js_response.status(), 200);
    let js_content_type = js_response.headers().get("content-type");
    assert!(js_content_type.is_some());
    let js_content_type_str = js_content_type.unwrap().to_str().into_diagnostic()?;
    assert!(
        js_content_type_str.contains("application/javascript")
            || js_content_type_str.contains("text/javascript")
    );

    let txt_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/readme.txt", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(txt_response.status(), 200);
    let txt_body = txt_response.text().await.into_diagnostic()?;
    assert!(txt_body.contains("Plain text file content"));

    Ok(())
}

#[tokio::test]
async fn test_404_handling() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let _daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/nonexistent.html", ports.http))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 404);

    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "nonexistent.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 404);

    Ok(())
}

#[tokio::test]
async fn test_https_single_certificate() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    create_and_insert_certificate(&daemon, "localhost", "cert.pem", "key.pem").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let setup_commands = vec![
        "sudo mkdir -p /var/makiatto/sites/localhost",
        "echo '<h1>HTTPS Test Page</h1>' | sudo tee /var/makiatto/sites/localhost/index.html",
    ];

    execute_commands(&daemon, &setup_commands).await?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .into_diagnostic()?;

    let https_response = client
        .get(format!("https://127.0.0.1:{}", ports.https))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(https_response.status(), 200);
    let https_body = https_response.text().await.into_diagnostic()?;
    assert!(https_body.contains("HTTPS Test Page"));

    Ok(())
}

#[tokio::test]
async fn test_https_sni_multiple_certificates() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    create_and_insert_certificate(&daemon, "example.com", "example.crt", "example.key").await?;
    create_and_insert_certificate(&daemon, "test.com", "test.crt", "test.key").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let setup_commands = vec![
        "sudo mkdir -p /var/makiatto/sites/example.com",
        "sudo mkdir -p /var/makiatto/sites/test.com",
        "echo '<h1>Example.com HTTPS</h1>' | sudo tee /var/makiatto/sites/example.com/index.html",
        "echo '<h1>Test.com HTTPS</h1>' | sudo tee /var/makiatto/sites/test.com/index.html",
    ];

    execute_commands(&daemon, &setup_commands).await?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .into_diagnostic()?;

    let example_response = client
        .get(format!("https://127.0.0.1:{}", ports.https))
        .header("Host", "example.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(example_response.status(), 200);
    let example_body = example_response.text().await.into_diagnostic()?;
    assert!(example_body.contains("Example.com HTTPS"));

    let test_response = client
        .get(format!("https://127.0.0.1:{}", ports.https))
        .header("Host", "test.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(test_response.status(), 200);
    let test_body = test_response.text().await.into_diagnostic()?;
    assert!(test_body.contains("Test.com HTTPS"));

    Ok(())
}

#[tokio::test]
async fn test_http_to_https_redirect() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    create_and_insert_certificate(&daemon, "localhost", "cert.pem", "key.pem").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .into_diagnostic()?;

    let http_response = client
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(http_response.status(), 308);
    let location = http_response.headers().get("location");
    assert!(location.is_some());
    let location_str = location.unwrap().to_str().into_diagnostic()?;
    assert!(location_str.starts_with("https://"));

    Ok(())
}

/// Helper function to execute a list of commands with logging
async fn execute_commands(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    commands: &[&str],
) -> Result<()> {
    for cmd in commands {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let mut result = daemon
            .exec(ExecCommand::new(vec!["sh", "-c", cmd]))
            .await
            .map_err(|e| miette!("Failed to execute command '{cmd}': {e}"))?;

        eprintln!("Command: {cmd}");
        eprintln!(
            "Stdout: {}",
            String::from_utf8_lossy(
                &result
                    .stdout_to_vec()
                    .await
                    .map_err(|e| miette!("Failed to get stdout: {e}"))?
            )
        );
        eprintln!(
            "Stderr: {}",
            String::from_utf8_lossy(
                &result
                    .stderr_to_vec()
                    .await
                    .map_err(|e| miette!("Failed to get stderr: {e}"))?
            )
        );
    }
    Ok(())
}

/// Helper function to generate and insert a certificate for a domain
async fn create_and_insert_certificate(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    domain: &str,
    cert_filename: &str,
    key_filename: &str,
) -> Result<()> {
    daemon
        .exec(ExecCommand::new(vec!["sudo", "mkdir", "-p", "/tmp/certs"]))
        .await
        .map_err(|e| miette!("Failed to create cert directory: {e}"))?;

    let openssl_cmd = format!(
        "sudo openssl req -x509 -newkey rsa:2048 -keyout /tmp/certs/{key_filename} -out /tmp/certs/{cert_filename} -days 1 -nodes -subj '/CN={domain}'",
    );

    let mut result = daemon
        .exec(ExecCommand::new(vec!["sh", "-c", &openssl_cmd]))
        .await
        .map_err(|e| miette!("Failed to execute openssl command: {e}"))?;

    let stderr = result.stderr_to_vec().await.unwrap_or_default();
    if !stderr.is_empty() {
        let stderr_str = String::from_utf8_lossy(&stderr);
        if stderr_str.contains("error") || stderr_str.contains("Error") {
            return Err(miette::miette!("OpenSSL command failed: {}", stderr_str));
        }
    }

    // Verify certificate files exist
    let cert_check = daemon
        .exec(ExecCommand::new(vec![
            "test",
            "-f",
            &format!("/tmp/certs/{cert_filename}"),
        ]))
        .await;
    let key_check = daemon
        .exec(ExecCommand::new(vec![
            "test",
            "-f",
            &format!("/tmp/certs/{key_filename}"),
        ]))
        .await;

    if cert_check.is_err() || key_check.is_err() {
        return Err(miette::miette!(
            "Certificate files were not created properly"
        ));
    }

    // Read certificate and key files
    let mut cert_result = daemon
        .exec(ExecCommand::new(vec![
            "cat",
            &format!("/tmp/certs/{cert_filename}"),
        ]))
        .await
        .map_err(|e| miette!("Failed to read cert: {e}"))?;

    let mut key_result = daemon
        .exec(ExecCommand::new(vec![
            "cat",
            &format!("/tmp/certs/{key_filename}"),
        ]))
        .await
        .map_err(|e| miette!("Failed to read key: {e}"))?;

    let cert_bytes = cert_result.stdout_to_vec().await.unwrap();
    let key_bytes = key_result.stdout_to_vec().await.unwrap();
    let cert_pem = String::from_utf8_lossy(&cert_bytes).trim().to_string();
    let key_pem = String::from_utf8_lossy(&key_bytes).trim().to_string();

    // Validate certificate format
    if !cert_pem.starts_with("-----BEGIN CERTIFICATE-----") {
        return Err(miette::miette!("Invalid certificate format"));
    }
    if !key_pem.starts_with("-----BEGIN PRIVATE KEY-----")
        && !key_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----")
    {
        return Err(miette::miette!("Invalid private key format"));
    }

    let cert_b64 = BASE64_STANDARD.encode(cert_pem.as_bytes());
    let key_b64 = BASE64_STANDARD.encode(key_pem.as_bytes());

    // Insert certificate into database
    let cert_sql = format!(
        "INSERT INTO certificates (domain, certificate_pem, private_key_pem, expires_at, issuer) VALUES ('{domain}', '{cert_b64}', '{key_b64}', {}, 'test')",
        jiff::Timestamp::now().as_second() + 86400
    );

    let json_payload = serde_json::to_string(&[cert_sql]).unwrap();

    let mut insert_result = daemon
        .exec(ExecCommand::new(vec![
            "curl",
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &json_payload,
            "http://127.0.0.1:8181/v1/transactions",
        ]))
        .await
        .map_err(|e| miette!("Failed to insert certificate: {e}"))?;

    let insert_bytes = insert_result.stdout_to_vec().await.unwrap();
    let response = String::from_utf8_lossy(&insert_bytes);
    if !response.contains("\"rows_affected\"") || response.contains("\"error\"") {
        return Err(miette!("Certificate insertion failed: {}", response));
    }

    Ok(())
}
