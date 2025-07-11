use miette::{Result, miette};
use serde::Deserialize;

use crate::ui;

type NodeInfo = (String, Option<String>, Option<f64>, Option<f64>);

/// Common HTTP headers for API requests
fn http_headers() -> Vec<String> {
    vec![
        "-s".to_string(),
        "-H".to_string(),
        format!(
            "User-Agent: makiatto-cli/{} (https://github.com/halcyonnouveau/makiatto)",
            env!("CARGO_PKG_VERSION")
        ),
        "-H".to_string(),
        "Accept: application/json".to_string(),
        "-H".to_string(),
    ]
}

#[derive(Debug, Deserialize)]
pub struct IpApiResponse {
    pub ip: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

pub fn detect_node_info(host: &str) -> Result<NodeInfo> {
    ui::action("Fetching IPv4 and geolocation data");
    let ipapi_url = if host == "localhost" || host == "127.0.0.1" {
        "https://ipapi.co/json/".to_string()
    } else {
        format!("https://ipapi.co/{host}/json/")
    };

    let mut curl_args = http_headers();
    curl_args.extend(["Accept-Language: en-US,en;q=0.9".to_string(), ipapi_url]);

    let json_output = std::process::Command::new("curl")
        .args(curl_args)
        .output()
        .map_err(|e| miette!("Failed to execute curl: {}", e))?;

    if !json_output.status.success() {
        return Err(miette!("Failed to fetch geolocation data"));
    }

    let json_str = String::from_utf8_lossy(&json_output.stdout);
    let geo_data: IpApiResponse = serde_json::from_str(&json_str)
        .map_err(|e| miette!("Failed to parse geolocation response: {}", e))?;

    let ipv4 = geo_data.ip;
    let latitude = geo_data.latitude;
    let longitude = geo_data.longitude;

    ui::action("Fetching IPv6 address");
    let mut ipv6_args = http_headers();
    ipv6_args.push("https://api6.ipify.org".to_string());

    let ipv6 = std::process::Command::new("curl")
        .args(ipv6_args)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let addr = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if addr.is_empty() || addr.contains("curl:") || addr.contains("error") {
                    None
                } else {
                    Some(addr)
                }
            } else {
                None
            }
        });

    Ok((ipv4, ipv6, latitude, longitude))
}
