use std::path::PathBuf;

use argh::FromArgs;
use miette::{Context, IntoDiagnostic, Result, miette};

use crate::ui;

/// manage WASM development
#[derive(FromArgs)]
#[argh(subcommand, name = "wasm")]
pub struct WasmCommand {
    #[argh(subcommand)]
    pub action: WasmAction,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum WasmAction {
    Fetch(FetchWit),
}

/// download WIT interface files for WASM development
#[derive(FromArgs)]
#[argh(subcommand, name = "fetch")]
pub struct FetchWit {
    /// output directory (default: ./wit)
    #[argh(option, short = 'o', default = "PathBuf::from(\"wit\")")]
    pub output: PathBuf,

    /// version/tag to download (default: latest)
    #[argh(option, short = 'v')]
    pub version: Option<String>,
}

const GITHUB_API_LATEST: &str =
    "https://api.github.com/repos/halcyonnouveau/makiatto/releases/latest";
const GITHUB_API_TAG: &str = "https://api.github.com/repos/halcyonnouveau/makiatto/releases/tags";

pub async fn fetch_wit(fetch: &FetchWit) -> Result<()> {
    ui::status("Fetching WIT interface files");

    if fetch.output.exists() {
        return Err(miette!(
            "Directory '{}' already exists. Please remove it or choose a different output directory.",
            fetch.output.display()
        ));
    }

    let download_url = if let Some(ref version) = fetch.version {
        ui::action(&format!("Fetching WIT files for version {}", version));
        get_release_asset_url(&format!("{}/{}", GITHUB_API_TAG, version)).await?
    } else {
        ui::action("Fetching latest WIT files");
        get_release_asset_url(GITHUB_API_LATEST).await?
    };

    ui::action("Downloading makiatto-wit.tar.gz");
    let response = reqwest::get(&download_url)
        .await
        .into_diagnostic()
        .context("Failed to download WIT files")?;

    if !response.status().is_success() {
        return Err(miette!("Failed to download: HTTP {}", response.status()));
    }

    let tarball_bytes = response
        .bytes()
        .await
        .into_diagnostic()
        .context("Failed to read response body")?;

    ui::action("Extracting WIT files");
    let tar = flate2::read::GzDecoder::new(&tarball_bytes[..]);
    let mut archive = tar::Archive::new(tar);

    if let Some(parent) = fetch.output.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .into_diagnostic()
                .context("Failed to create parent directory")?;
        }
    }

    let temp_dir = std::env::temp_dir().join(format!("makiatto-wit-{}", uuid::Uuid::new_v4()));
    archive
        .unpack(&temp_dir)
        .into_diagnostic()
        .context("Failed to extract tarball")?;

    let extracted_wit = temp_dir.join("makiatto-wit").join("wit");
    std::fs::rename(&extracted_wit, &fetch.output)
        .into_diagnostic()
        .with_context(|| format!("Failed to move WIT files to {}", fetch.output.display()))?;

    let _ = std::fs::remove_dir_all(temp_dir);

    ui::status(&format!(
        "WIT files installed to {}",
        fetch.output.display()
    ));
    ui::info("You can now build WASM components using these interface definitions");
    ui::info("Example structure:");
    ui::info("  wit/http/http-handler.wit    - For HTTP functions");
    ui::info("  wit/transform/transform.wit  - For file transforms");

    Ok(())
}

async fn get_release_asset_url(api_url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent("makiatto-cli")
        .build()
        .into_diagnostic()
        .context("Failed to create HTTP client")?;

    let response = client
        .get(api_url)
        .send()
        .await
        .into_diagnostic()
        .context("Failed to fetch release information")?;

    if !response.status().is_success() {
        return Err(miette!(
            "GitHub API request failed: HTTP {}",
            response.status()
        ));
    }

    let release: serde_json::Value = response
        .json()
        .await
        .into_diagnostic()
        .context("Failed to parse GitHub API response")?;

    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| miette!("No assets found in release"))?;

    for asset in assets {
        if let Some(name) = asset["name"].as_str() {
            if name == "makiatto-wit.tar.gz" {
                if let Some(url) = asset["browser_download_url"].as_str() {
                    return Ok(url.to_string());
                }
            }
        }
    }

    Err(miette!("makiatto-wit.tar.gz not found in release assets"))
}
