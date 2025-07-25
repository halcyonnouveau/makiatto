#![cfg(test)]
use miette::{IntoDiagnostic, Result, miette};
use testcontainers::core::ExecCommand;

use crate::container::{ContainerContext, TestContainer};

#[tokio::test]
async fn test_web_virtual_hosting() -> Result<()> {
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
                    .stdout_to_vec()
                    .await
                    .map_err(|e| miette!("Failed to get stderr: {e}"))?
            )
        );
    }

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
async fn test_web_static_file_serving() -> Result<()> {
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
                    .stdout_to_vec()
                    .await
                    .map_err(|e| miette!("Failed to get stderr: {e}"))?
            )
        );
    }

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
async fn test_web_404_handling() -> Result<()> {
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
