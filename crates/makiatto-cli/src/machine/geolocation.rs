use miette::{Result, miette};
use serde::Deserialize;

use crate::ui;

/// Type alias for node information: (ipv4, ipv6, latitude, longitude)
type NodeInfo = (String, Option<String>, Option<f64>, Option<f64>);

#[derive(Debug, Deserialize)]
pub struct IpApiResponse {
    pub ip: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

pub fn detect_node_info(host: &str) -> Result<NodeInfo> {
    ui::action("Fetching IPv4 and geolocation data");
    let ipapi_url = format!("https://ipapi.co/{host}/json/");
    let json_output = std::process::Command::new("curl")
        .args(["-s", &ipapi_url])
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
    let ipv6 = std::process::Command::new("curl")
        .args(["-s", "https://api6.ipify.org"])
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
