#![cfg(test)]
use miette::{IntoDiagnostic, Result};

use crate::container::{ContainerContext, TestContainer};

fn setup_test_images(container_name: &str) -> Result<()> {
    let runtime = ContainerContext::detect_container_runtime()?;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|e| miette::miette!("Failed to get manifest dir: {e}"))?;
    let images_path = format!("{manifest_dir}/fixtures/images");

    // Create directory and copy images using container runtime
    let create_dir = std::process::Command::new(runtime)
        .args([
            "exec",
            container_name,
            "sudo",
            "mkdir",
            "-p",
            "/var/makiatto/sites/localhost/images",
        ])
        .output()
        .into_diagnostic()?;

    if !create_dir.status.success() {
        return Err(miette::miette!("Failed to create images directory"));
    }

    // Copy each image file
    for image in &["makiatto.png", "space.jpg", "memes.webp"] {
        let src = format!("{images_path}/{image}");
        let dst = format!("{container_name}:/tmp/{image}");

        let copy = std::process::Command::new(runtime)
            .args(["cp", &src, &dst])
            .output()
            .into_diagnostic()?;

        if !copy.status.success() {
            return Err(miette::miette!("Failed to copy {}", image));
        }

        // Move to final location with correct permissions
        let mv = std::process::Command::new(runtime)
            .args([
                "exec",
                container_name,
                "sudo",
                "mv",
                &format!("/tmp/{image}"),
                &format!("/var/makiatto/sites/localhost/images/{image}"),
            ])
            .output()
            .into_diagnostic()?;

        if !mv.status.success() {
            return Err(miette::miette!("Failed to move {}", image));
        }
    }

    // Fix permissions
    let chown = std::process::Command::new(runtime)
        .args([
            "exec",
            container_name,
            "sudo",
            "chown",
            "-R",
            "makiatto:makiatto",
            "/var/makiatto/sites/localhost",
        ])
        .output()
        .into_diagnostic()?;

    if !chown.status.success() {
        return Err(miette::miette!("Failed to chown images"));
    }

    Ok(())
}

#[tokio::test]
async fn test_image_resize_basic() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        id,
        ..
    } = context.make_daemon().await?;

    let _daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    setup_test_images(&format!("{id}-wawa-daemon"))?;

    // Request resized image
    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/images/space.jpg?w=400",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);

    let content_type = response.headers().get("content-type");
    assert!(content_type.is_some());
    let content_type_str = content_type.unwrap().to_str().into_diagnostic()?;
    assert!(content_type_str.contains("image/jpeg"));

    let body_bytes = response.bytes().await.into_diagnostic()?;
    // Resized image should be smaller than original (~350KB)
    assert!(body_bytes.len() < 350_010);
    // But not too small (sanity check)
    assert!(body_bytes.len() > 1000);

    Ok(())
}

#[tokio::test]
async fn test_image_format_conversion() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        id,
        ..
    } = context.make_daemon().await?;

    let _daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    setup_test_images(&format!("{id}-wawa-daemon"))?;

    // Convert PNG to WebP
    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/images/makiatto.png?fmt=webp",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);

    let content_type = response.headers().get("content-type");
    assert!(content_type.is_some());
    let content_type_str = content_type.unwrap().to_str().into_diagnostic()?;
    assert_eq!(content_type_str, "image/webp");

    let body_bytes = response.bytes().await.into_diagnostic()?;
    // WebP should be smaller than original PNG (949KB)
    assert!(body_bytes.len() < 949_000);
    assert!(body_bytes.len() > 1000);

    Ok(())
}

#[tokio::test]
async fn test_image_quality_param() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        id,
        ..
    } = context.make_daemon().await?;

    let _daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    setup_test_images(&format!("{id}-wawa-daemon"))?;

    // Request with low quality
    let response_low = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/images/space.jpg?q=50",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response_low.status(), 200);

    let body_low = response_low.bytes().await.into_diagnostic()?;

    // Request with high quality
    let response_high = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/images/space.jpg?q=95",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response_high.status(), 200);

    let body_high = response_high.bytes().await.into_diagnostic()?;

    // Low quality should be smaller than high quality
    assert!(body_low.len() < body_high.len());

    Ok(())
}

#[tokio::test]
async fn test_cache_behavior() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        id,
        ..
    } = context.make_daemon().await?;

    let _daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    setup_test_images(&format!("{id}-wawa-daemon"))?;

    let url = format!(
        "http://127.0.0.1:{}/images/memes.webp?w=200&fmt=jpg",
        ports.http
    );

    // First request (cache miss)
    let response1 = reqwest::Client::new()
        .get(&url)
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response1.status(), 200);
    let body1 = response1.bytes().await.into_diagnostic()?;

    // Second request (cache hit)
    let response2 = reqwest::Client::new()
        .get(&url)
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response2.status(), 200);
    let body2 = response2.bytes().await.into_diagnostic()?;

    // Both requests should return identical content
    assert_eq!(body1.len(), body2.len());
    assert_eq!(body1.as_ref(), body2.as_ref());

    Ok(())
}

#[tokio::test]
async fn test_original_url_unchanged() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        id,
        ..
    } = context.make_daemon().await?;

    let _daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    setup_test_images(&format!("{id}-wawa-daemon"))?;

    // Request without any query parameters (should serve original file)
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/images/space.jpg", ports.http))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);

    let content_type = response.headers().get("content-type");
    assert!(content_type.is_some());

    let body_bytes = response.bytes().await.into_diagnostic()?;
    // Original file should be ~350KB
    // Allow some tolerance for filesystem metadata
    assert!(body_bytes.len() > 340_000);
    assert!(body_bytes.len() < 360_000);

    Ok(())
}

#[tokio::test]
async fn test_invalid_params_fallback() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        id,
        ..
    } = context.make_daemon().await?;

    let _daemon = daemon_container.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    setup_test_images(&format!("{id}-wawa-daemon"))?;

    // Request with width exceeding max (default max is 4096)
    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/images/space.jpg?w=9999",
            ports.http
        ))
        .header("Host", "localhost")
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);

    let body_bytes = response.bytes().await.into_diagnostic()?;
    // Should serve original file (fallback behavior)
    assert!(body_bytes.len() > 340_000);
    assert!(body_bytes.len() < 360_000);

    Ok(())
}
