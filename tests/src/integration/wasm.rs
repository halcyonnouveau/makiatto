#![cfg(test)]
use miette::{IntoDiagnostic, Result};

use crate::container::{ContainerContext, TestContainer, util};

#[tokio::test]
async fn test_wasm_function_basic_execution() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Setup directories and copy WASM file
    let commands = vec![
        "sudo mkdir -p /var/makiatto/sites/localhost/api",
        "sudo bash -c 'echo \"<h1>Static fallback</h1>\" > /var/makiatto/sites/localhost/index.html'",
    ];
    util::execute_commands(&daemon, &commands).await?;

    // Copy WASM file from tests/fixtures/wasm to container
    let wasm_copy_cmd = format!(
        "{} cp {}/tests/fixtures/wasm/simple-handler.wasm {}:/var/makiatto/sites/localhost/api/hello.wasm",
        context.runtime,
        context.root.display(),
        daemon.id()
    );
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&wasm_copy_cmd)
        .output()
        .await
        .into_diagnostic()?;

    util::execute_command(
        &daemon,
        "sudo chown -R makiatto:makiatto /var/makiatto/sites/localhost",
    )
    .await?;

    // Insert function metadata into database
    let env_json = serde_json::to_string(&serde_json::json!({"TEST_VAR": "test_value"})).unwrap();
    let methods_json = serde_json::to_string(&["GET", "POST"]).unwrap();
    let timestamp = util::current_timestamp();

    let function_sql = format!(
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/hello', 'localhost', 'api/hello.wasm', '{}', '{}', 5000, 128, {})",
        methods_json, env_json, timestamp
    );

    util::execute_transactions(&daemon, &[function_sql]).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Test GET request to WASM function
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/api/hello", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);

    let body = response.text().await.into_diagnostic()?;
    assert!(body.contains("Method::Get"));
    assert!(body.contains("Path: /api/hello"));

    // Test POST request
    let post_response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/hello", ports.http))
        .header("Host", "localhost")
        .body("test body")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(post_response.status(), 200);
    let post_body = post_response.text().await.into_diagnostic()?;
    assert!(post_body.contains("Method::Post"));

    // Test that static file still works (not overridden by WASM)
    let static_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(static_response.status(), 200);
    let static_body = static_response.text().await.into_diagnostic()?;
    assert!(static_body.contains("Static fallback"));

    Ok(())
}

#[tokio::test]
async fn test_wasm_function_method_filtering() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Setup directories and copy WASM file
    util::execute_command(&daemon, "sudo mkdir -p /var/makiatto/sites/localhost/api").await?;

    let wasm_copy_cmd = format!(
        "{} cp {}/tests/fixtures/wasm/simple-handler.wasm {}:/var/makiatto/sites/localhost/api/post-only.wasm",
        context.runtime,
        context.root.display(),
        daemon.id()
    );
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&wasm_copy_cmd)
        .output()
        .await
        .into_diagnostic()?;

    util::execute_command(
        &daemon,
        "sudo chown -R makiatto:makiatto /var/makiatto/sites/localhost",
    )
    .await?;

    // Insert function with POST-only method filtering
    let env_json = serde_json::to_string(&serde_json::json!({})).unwrap();
    let methods_json = serde_json::to_string(&["POST"]).unwrap();
    let timestamp = util::current_timestamp();

    let function_sql = format!(
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/post-only', 'localhost', 'api/post-only.wasm', '{}', '{}', 5000, 128, {})",
        methods_json, env_json, timestamp
    );

    util::execute_transactions(&daemon, &[function_sql]).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Test POST request (should work)
    let post_response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/post-only", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(post_response.status(), 200);

    // Test GET request (should return 404 - filtered out)
    let get_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/api/post-only", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(get_response.status(), 404);

    Ok(())
}

#[tokio::test]
async fn test_wasm_function_with_query_params() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    util::execute_command(&daemon, "sudo mkdir -p /var/makiatto/sites/localhost/api").await?;

    let wasm_copy_cmd = format!(
        "{} cp {}/tests/fixtures/wasm/simple-handler.wasm {}:/var/makiatto/sites/localhost/api/query.wasm",
        context.runtime,
        context.root.display(),
        daemon.id()
    );
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&wasm_copy_cmd)
        .output()
        .await
        .into_diagnostic()?;

    util::execute_command(
        &daemon,
        "sudo chown -R makiatto:makiatto /var/makiatto/sites/localhost",
    )
    .await?;

    let env_json = serde_json::to_string(&serde_json::json!({})).unwrap();
    let timestamp = util::current_timestamp();

    let function_sql = format!(
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/query', 'localhost', 'api/query.wasm', NULL, '{}', 5000, 128, {})",
        env_json, timestamp
    );

    util::execute_transactions(&daemon, &[function_sql]).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Test with query parameters
    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/api/query?foo=bar&baz=qux",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);

    let body = response.text().await.into_diagnostic()?;
    assert!(body.contains("Query: Some(\"foo=bar&baz=qux\")"));

    Ok(())
}

#[tokio::test]
async fn test_wasm_function_with_headers() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    util::execute_command(&daemon, "sudo mkdir -p /var/makiatto/sites/localhost/api").await?;

    let wasm_copy_cmd = format!(
        "{} cp {}/tests/fixtures/wasm/simple-handler.wasm {}:/var/makiatto/sites/localhost/api/headers.wasm",
        context.runtime,
        context.root.display(),
        daemon.id()
    );
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&wasm_copy_cmd)
        .output()
        .await
        .into_diagnostic()?;

    util::execute_command(
        &daemon,
        "sudo chown -R makiatto:makiatto /var/makiatto/sites/localhost",
    )
    .await?;

    let env_json = serde_json::to_string(&serde_json::json!({})).unwrap();
    let timestamp = util::current_timestamp();

    let function_sql = format!(
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/headers', 'localhost', 'api/headers.wasm', NULL, '{}', 5000, 128, {})",
        env_json, timestamp
    );

    util::execute_transactions(&daemon, &[function_sql]).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Test with custom headers
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/api/headers", ports.http))
        .header("Host", "localhost")
        .header("X-Custom-Header", "custom-value")
        .header("Authorization", "Bearer token123")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain"
    );

    let body = response.text().await.into_diagnostic()?;
    assert!(body.contains("x-custom-header"));
    assert!(body.contains("authorization"));

    Ok(())
}
