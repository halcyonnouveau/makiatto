#![cfg(test)]
use miette::{IntoDiagnostic, Result};

use crate::container::{ContainerContext, TestContainer, util};

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

    util::execute_commands(&daemon, &commands).await?;

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

    let commands = vec![
        "sudo mkdir -p /var/makiatto/sites/localhost/assets",
        "echo '<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Test Page</h1></body></html>' | sudo tee /var/makiatto/sites/localhost/index.html",
        "echo 'body { color: red; }' | sudo tee /var/makiatto/sites/localhost/assets/style.css",
        "echo 'console.log(\"Hello world\");' | sudo tee /var/makiatto/sites/localhost/assets/script.js",
        "echo 'Plain text file content' | sudo tee /var/makiatto/sites/localhost/readme.txt",
        "sudo chown -R makiatto:makiatto /var/makiatto/sites",
    ];

    util::execute_commands(&daemon, &commands).await?;

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

    util::generate_tls_certificate(&daemon, "localhost", "cert.pem", "key.pem").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let setup_commands = vec![
        "sudo mkdir -p /var/makiatto/sites/localhost",
        "echo '<h1>HTTPS Test Page</h1>' | sudo tee /var/makiatto/sites/localhost/index.html",
    ];

    util::execute_commands(&daemon, &setup_commands).await?;

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

    util::generate_tls_certificate(&daemon, "example.com", "example.crt", "example.key").await?;
    util::generate_tls_certificate(&daemon, "test.com", "test.crt", "test.key").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let setup_commands = vec![
        "sudo mkdir -p /var/makiatto/sites/example.com",
        "sudo mkdir -p /var/makiatto/sites/test.com",
        "echo '<h1>Example.com HTTPS</h1>' | sudo tee /var/makiatto/sites/example.com/index.html",
        "echo '<h1>Test.com HTTPS</h1>' | sudo tee /var/makiatto/sites/test.com/index.html",
    ];

    util::execute_commands(&daemon, &setup_commands).await?;

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

    util::generate_tls_certificate(&daemon, "localhost", "cert.pem", "key.pem").await?;

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

#[tokio::test]
async fn test_domain_alias_web_serving() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    util::execute_command(&daemon, "sudo mkdir -p /var/makiatto/sites/dog.com").await?;
    util::execute_command(
        &daemon,
        "echo '<h1>Hello from dog.com</h1>' | sudo tee /var/makiatto/sites/dog.com/index.html",
    )
    .await?;

    // Insert domain alias: frog.com -> dog.com
    let sql = "INSERT INTO domain_aliases (alias, target) VALUES ('frog.com', 'dog.com')";
    util::execute_transaction(&daemon, sql).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Test that frog.com serves content from dog.com
    let frog_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "frog.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(frog_response.status(), 200);
    let frog_body = frog_response.text().await.into_diagnostic()?;
    assert!(
        frog_body.contains("Hello from dog.com"),
        "frog.com should serve content from dog.com"
    );

    // Test that dog.com still works directly
    let dog_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "dog.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(dog_response.status(), 200);
    let dog_body = dog_response.text().await.into_diagnostic()?;
    assert!(
        dog_body.contains("Hello from dog.com"),
        "dog.com should serve its own content"
    );

    // Test that a non-aliased domain returns 404
    let cat_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "cat.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(cat_response.status(), 404);
    let cat_body = cat_response.text().await.into_diagnostic()?;
    assert!(
        cat_body.contains("Domain 'cat.com' not found"),
        "Non-existent domain should return 404"
    );

    Ok(())
}

#[tokio::test]
async fn test_domain_alias_chain() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    util::execute_command(&daemon, "sudo mkdir -p /var/makiatto/sites/target.com").await?;
    util::execute_command(
        &daemon,
        "echo '<h1>Final target content</h1>' | sudo tee /var/makiatto/sites/target.com/index.html",
    )
    .await?;

    // Insert alias chain: first.com -> second.com -> target.com
    let sql1 = "INSERT INTO domain_aliases (alias, target) VALUES ('first.com', 'second.com')";
    let sql2 = "INSERT INTO domain_aliases (alias, target) VALUES ('second.com', 'target.com')";
    util::execute_transaction(&daemon, sql1).await?;
    util::execute_transaction(&daemon, sql2).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Test that first.com resolves through the chain to target.com
    let first_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "first.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(first_response.status(), 200);
    let first_body = first_response.text().await.into_diagnostic()?;
    assert!(
        first_body.contains("Final target content"),
        "first.com should resolve through chain to target.com"
    );

    Ok(())
}

#[tokio::test]
async fn test_domain_alias_loop_protection() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    util::execute_command(&daemon, "sudo mkdir -p /var/makiatto/sites/loop1.com").await?;
    util::execute_command(
        &daemon,
        "echo '<h1>Loop1 content</h1>' | sudo tee /var/makiatto/sites/loop1.com/index.html",
    )
    .await?;

    // Insert circular alias: loop1.com -> loop2.com -> loop1.com
    let sql1 = "INSERT INTO domain_aliases (alias, target) VALUES ('loop1.com', 'loop2.com')";
    let sql2 = "INSERT INTO domain_aliases (alias, target) VALUES ('loop2.com', 'loop1.com')";
    util::execute_transaction(&daemon, sql1).await?;
    util::execute_transaction(&daemon, sql2).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Test that loop1.com still works (loop protection should return original domain)
    let loop_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}", ports.http))
        .header("Host", "loop1.com")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(loop_response.status(), 200);
    let loop_body = loop_response.text().await.into_diagnostic()?;
    assert!(
        loop_body.contains("Loop1 content"),
        "Loop protection should allow loop1.com to serve its own content"
    );

    Ok(())
}
