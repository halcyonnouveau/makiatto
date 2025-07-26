use miette::{Result, miette};
use serde::Deserialize;

use crate::ui;

type NodeInfo = (String, Option<String>, Option<f64>, Option<f64>);

#[derive(Debug, Deserialize)]
pub struct IpApiResponse {
    pub ip: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

pub async fn detect_node_info(host: &str) -> Result<NodeInfo> {
    ui::action("Fetching IPv4 and geolocation data");
    let ipapi_url = if host == "localhost" || host == "127.0.0.1" {
        "https://ipapi.co/json/"
    } else {
        &format!("https://ipapi.co/{host}/json/")
    };

    let client = reqwest::Client::builder()
        .user_agent(format!(
            "makiatto-cli/{} (https://github.com/halcyonnouveau/makiatto)",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| miette!("Failed to create HTTP client: {e}"))?;

    // Retry geolocation API with exponential backoff
    let mut last_error = None;

    for attempt in 1..=3 {
        match client
            .get(ipapi_url)
            .header("Accept", "application/json")
            .header("Accept-Language", "en-US,en;q=0.9")
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<IpApiResponse>().await {
                        Ok(geo_data) => {
                            let ipv4 = geo_data.ip;
                            let latitude = geo_data.latitude;
                            let longitude = geo_data.longitude;

                            let ipv6 = fetch_ipv6_with_retry(&client).await;
                            return Ok((ipv4, ipv6, latitude, longitude));
                        }
                        Err(e) => {
                            last_error = Some(miette!(
                                "Failed to parse geolocation response (attempt {attempt}): {e}"
                            ));
                        }
                    }
                } else {
                    last_error = Some(miette!(
                        "HTTP error (attempt {attempt}): {}",
                        response.status()
                    ));
                }
            }
            Err(e) => {
                last_error = Some(miette!("Network error (attempt {attempt}): {e}"));
            }
        }

        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_millis(1000 * attempt)).await;
        }
    }

    Err(last_error.unwrap_or_else(|| miette!("All geolocation attempts failed")))
}

async fn fetch_ipv6_with_retry(client: &reqwest::Client) -> Option<String> {
    ui::action("Fetching IPv6 address");

    for _ in 1..=2 {
        if let Ok(response) = client
            .get("https://api6.ipify.org")
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            && response.status().is_success()
            && let Ok(addr) = response.text().await
        {
            let addr = addr.trim().to_string();
            if !addr.is_empty() && !addr.contains("error") {
                return Some(addr);
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    None
}
