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
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/hello', 'localhost', 'api/hello.wasm', '{methods_json}', '{env_json}', 5000, 128, {timestamp})"
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
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/post-only', 'localhost', 'api/post-only.wasm', '{methods_json}', '{env_json}', 5000, 128, {timestamp})"
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
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/query', 'localhost', 'api/query.wasm', NULL, '{env_json}', 5000, 128, {timestamp})"
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
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/headers', 'localhost', 'api/headers.wasm', NULL, '{env_json}', 5000, 128, {timestamp})"
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
#[tokio::test]
async fn test_wasm_transform_basic_execution() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Setup directories and create a test HTML file
    let commands = vec![
        "sudo mkdir -p /var/makiatto/sites/localhost",
        "sudo bash -c 'echo \"<html><body>Hello</body></html>\" > /var/makiatto/sites/localhost/index.html'",
    ];
    util::execute_commands(&daemon, &commands).await?;

    // Copy WASM transformer from tests/fixtures/wasm to container
    let wasm_copy_cmd = format!(
        "{} cp {}/tests/fixtures/wasm/simple-transformer.wasm {}:/var/makiatto/sites/localhost/transform.wasm",
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

    // Insert transform metadata into database
    let env_json = serde_json::to_string(&serde_json::json!({})).unwrap();
    let timestamp = util::current_timestamp();
    let transform_sql = format!(
        "INSERT INTO domain_transforms (id, domain, path, files_pattern, env, timeout_ms, max_memory_mb, execution_order, updated_at) VALUES ('localhost:transform.wasm:0', 'localhost', 'transform.wasm', '*.html', '{env_json}', 5000, 128, 0, {timestamp})"
    );

    util::execute_transactions(&daemon, &[transform_sql]).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Request the HTML file - should be transformed
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/index.html", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);

    let body = response.text().await.into_diagnostic()?;

    // Should contain the WASM transform comment with node context
    assert!(body.contains("<!-- Transformed by WASM on node"));
    assert!(body.contains("/index.html -->"));
    // Should still contain original content
    assert!(body.contains("<html><body>Hello</body></html>"));

    Ok(())
}

#[tokio::test]
async fn test_wasm_transform_glob_pattern_matching() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Setup directories with different file types
    let commands = vec![
        "sudo mkdir -p /var/makiatto/sites/localhost/css",
        "sudo bash -c 'echo \"<html><body>Page</body></html>\" > /var/makiatto/sites/localhost/index.html'",
        "sudo bash -c 'echo \"body { color: red; }\" > /var/makiatto/sites/localhost/css/style.css'",
        "sudo bash -c 'echo \"console.log(\\\"test\\\");\" > /var/makiatto/sites/localhost/app.js'",
    ];
    util::execute_commands(&daemon, &commands).await?;

    // Copy WASM transformer
    let wasm_copy_cmd = format!(
        "{} cp {}/tests/fixtures/wasm/simple-transformer.wasm {}:/var/makiatto/sites/localhost/transform.wasm",
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

    // Insert transforms with different glob patterns
    let env_json = serde_json::to_string(&serde_json::json!({})).unwrap();
    let timestamp = util::current_timestamp();

    let transforms = vec![
        format!(
            "INSERT INTO domain_transforms (id, domain, path, files_pattern, env, execution_order, updated_at) VALUES ('localhost:transform.wasm:0', 'localhost', 'transform.wasm', '*.html', '{}', 0, {})",
            env_json, timestamp
        ),
        format!(
            "INSERT INTO domain_transforms (id, domain, path, files_pattern, env, execution_order, updated_at) VALUES ('localhost:transform.wasm:1', 'localhost', 'transform.wasm', '**/*.js', '{}', 1, {})",
            env_json, timestamp
        ),
    ];

    util::execute_transactions(&daemon, &transforms).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Test HTML file - should match *.html pattern
    let html_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/index.html", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    let html_body = html_response.text().await.into_diagnostic()?;
    assert!(html_body.contains("<!-- Transformed by WASM"));

    // Test JS file - should match **/*.js pattern
    let js_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/app.js", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    let js_body = js_response.text().await.into_diagnostic()?;
    assert!(js_body.contains("// Transformed by node"));

    // Test CSS file - should NOT match any pattern
    let css_response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/css/style.css", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    let css_body = css_response.text().await.into_diagnostic()?;
    assert!(!css_body.contains("Transformed"));
    assert!(css_body.contains("body { color: red; }"));

    Ok(())
}

#[tokio::test]
async fn test_wasm_transform_sequential_execution() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Setup test file
    let commands = vec![
        "sudo mkdir -p /var/makiatto/sites/localhost",
        "sudo bash -c 'echo \"<html>Original</html>\" > /var/makiatto/sites/localhost/test.html'",
    ];
    util::execute_commands(&daemon, &commands).await?;

    // Copy WASM transformer
    let wasm_copy_cmd = format!(
        "{} cp {}/tests/fixtures/wasm/simple-transformer.wasm {}:/var/makiatto/sites/localhost/transform.wasm",
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

    // Insert multiple transforms with different execution orders
    let env_json = serde_json::to_string(&serde_json::json!({})).unwrap();
    let timestamp = util::current_timestamp();

    // Note: Same transformer applied twice with different execution orders
    // The transform should be applied sequentially
    let transforms = vec![
        format!(
            "INSERT INTO domain_transforms (id, domain, path, files_pattern, env, execution_order, updated_at) VALUES ('localhost:transform.wasm:0', 'localhost', 'transform.wasm', '*.html', '{}', 0, {})",
            env_json, timestamp
        ),
        format!(
            "INSERT INTO domain_transforms (id, domain, path, files_pattern, env, execution_order, updated_at) VALUES ('localhost:transform.wasm:1', 'localhost', 'transform.wasm', '*.html', '{}', 1, {})",
            env_json, timestamp
        ),
    ];

    util::execute_transactions(&daemon, &transforms).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Request the file - both transforms should be applied in order
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/test.html", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);

    let body = response.text().await.into_diagnostic()?;

    // Should contain nested transform comments (first transform wraps, second transform wraps that)
    let comment_count = body.matches("<!-- Transformed by WASM").count();
    assert_eq!(
        comment_count, 2,
        "Expected 2 transform comments for sequential execution"
    );

    // Should still contain original content
    assert!(body.contains("<html>Original</html>"));

    Ok(())
}

#[tokio::test]
async fn test_wasm_ssrf_protection() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Setup directories and copy SSRF test WASM file
    util::execute_command(&daemon, "sudo mkdir -p /var/makiatto/sites/localhost/api").await?;

    let wasm_copy_cmd = format!(
        "{} cp {}/tests/fixtures/wasm/ssrf-test.wasm {}:/var/makiatto/sites/localhost/api/ssrf.wasm",
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

    // Insert function metadata
    let env_json = serde_json::to_string(&serde_json::json!({})).unwrap();
    let timestamp = util::current_timestamp();

    let function_sql = format!(
        "INSERT INTO domain_functions (id, domain, path, methods, env, timeout_ms, max_memory_mb, updated_at) VALUES ('localhost:/api/ssrf', 'localhost', 'api/ssrf.wasm', NULL, '{env_json}', 5000, 128, {timestamp})"
    );

    util::execute_transactions(&daemon, &[function_sql]).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Attempt to connect to localhost (should be blocked)
    let localhost_response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/api/ssrf?target=127.0.0.1:80",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(localhost_response.status(), 200);
    let localhost_body = localhost_response.text().await.into_diagnostic()?;
    assert!(localhost_body.contains("BLOCKED"));

    // Attempt to connect to private IP (should be blocked)
    let private_response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/api/ssrf?target=192.168.1.1:80",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(private_response.status(), 200);
    let private_body = private_response.text().await.into_diagnostic()?;
    assert!(private_body.contains("BLOCKED"));

    // Attempt to connect to AWS metadata endpoint (should be blocked)
    let metadata_response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/api/ssrf?target=169.254.169.254:80",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(metadata_response.status(), 200);
    let metadata_body = metadata_response.text().await.into_diagnostic()?;
    assert!(metadata_body.contains("BLOCKED"));

    // Connect to public IP should work (or at least not be blocked by SSRF protection)
    // Using 8.8.8.8:80 (Google DNS) - might fail for other reasons but shouldn't be blocked
    let public_response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/api/ssrf?target=8.8.8.8:80",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(public_response.status(), 200);

    Ok(())
}
