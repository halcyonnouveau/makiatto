use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use argh::FromArgs;
use console::style;
use futures::future::join_all;
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::xfer::Protocol,
};
use miette::{Result, miette};
use reqwest::header::{HOST, HeaderMap, HeaderValue};
use tokio::time::timeout;

use crate::{
    config::{Config, Machine, Profile},
    ssh::SshSession,
    ui,
};

/// show cluster health
#[derive(FromArgs)]
#[argh(subcommand, name = "health")]
pub struct HealthCommand {
    /// path to SSH private key (optional)
    #[argh(option, long = "ssh-priv-key")]
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct NodeHealth {
    name: Arc<str>,
    consensus: ConsensusStatus,
    system: SystemStatus,
    dns: Option<DnsStatus>,
    web: Vec<DomainStatus>,
}

#[derive(Debug, Clone)]
struct ConsensusStatus {
    healthy: bool,
    leader: Option<String>,
    term: Option<i64>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct SystemStatus {
    healthy: bool,
    memory_percent: Option<f64>,
    disk_percent: Option<f64>,
    load_average: Option<f64>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct DnsStatus {
    healthy: bool,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct DomainStatus {
    domain: Arc<str>,
    healthy: bool,
    is_https: bool,
    cert_days_remaining: Option<i64>,
    error: Option<String>,
}

/// Performs comprehensive health checks on all nodes in the makiatto cluster.
///
/// This function checks:
/// - Cluster consensus (leader election state)
/// - Web server health for all configured domains
/// - DNS server health (for nameserver nodes)
/// - System resources (memory, disk, load)
///
/// # Errors
/// Returns an error if:
/// - No machines are configured in the profile
/// - Unable to connect to the sync target to retrieve certificates
/// - Critical SSH connection failures prevent any health checks
pub async fn check_health(
    command: &HealthCommand,
    profile: &Profile,
    config: &Config,
) -> Result<()> {
    if profile.machines.is_empty() {
        return Err(miette!(
            "No machines configured. Use `machine init` to add one first"
        ));
    }

    ui::status("Running health checks...");

    let sync_target = profile
        .machines
        .iter()
        .find(|m| m.sync_target)
        .unwrap_or(&profile.machines[0]);

    let certificates = get_certs(sync_target, command.key_path.as_ref())?;

    let health_futures: Vec<_> = profile
        .machines
        .iter()
        .map(|machine| {
            let machine = machine.clone();
            let config = config.clone();
            let certificates = certificates.clone();
            let key_path = command.key_path.clone();

            tokio::spawn(async move {
                check_node_health(&machine, &config, &certificates, key_path.as_ref()).await
            })
        })
        .collect();

    let health_results: Vec<NodeHealth> = join_all(health_futures)
        .await
        .into_iter()
        .filter_map(std::result::Result::ok)
        .collect();

    let consensus_ok = check_consensus_agreement(&health_results);

    // Display results
    display_health_results(&health_results, consensus_ok);

    Ok(())
}

fn get_certs(sync_target: &Machine, key_path: Option<&PathBuf>) -> Result<HashMap<String, i64>> {
    let ssh = SshSession::new(&sync_target.ssh_target, sync_target.port, key_path)?;

    let query = "SELECT domain, expires_at FROM certificates";
    let cmd =
        format!("sudo -u makiatto sqlite3 /var/makiatto/cluster.db -separator '|' \"{query}\"");

    let output = ssh.exec(&cmd).unwrap_or_default();

    let mut certificates = HashMap::new();
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() == 2
            && let Ok(expires_at) = parts[1].parse::<i64>()
        {
            certificates.insert(parts[0].to_string(), expires_at);
        }
    }

    Ok(certificates)
}

async fn check_node_health(
    machine: &Machine,
    config: &Config,
    certificates: &HashMap<String, i64>,
    key_path: Option<&PathBuf>,
) -> NodeHealth {
    let ssh = SshSession::new(&machine.ssh_target, machine.port, key_path).unwrap();

    let consensus = check_consensus(&ssh).await;
    let system = check_system_health(&ssh).await;

    let dns = if machine.is_nameserver {
        Some(check_dns_health(machine, config).await)
    } else {
        None
    };

    let web = check_web_domains(machine, config, certificates).await;

    NodeHealth {
        name: machine.name.clone(),
        consensus,
        system,
        dns,
        web,
    }
}

async fn check_consensus(ssh: &SshSession) -> ConsensusStatus {
    let ssh = ssh.clone();

    match tokio::task::spawn_blocking(move || {
        let query = "SELECT node_name, role, term FROM cluster_leadership LIMIT 1";
        let cmd = format!("sqlite3 /var/makiatto/cluster.db -separator '|' \"{query}\"");

        let output = ssh.exec(&cmd)?;
        let line = output.lines().next().unwrap_or("");

        if line.trim().is_empty() {
            return Ok::<(Option<String>, Option<i64>), miette::Error>((None, None));
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 3 {
            let leader = parts[0].to_string();
            let term = parts[2].parse::<i64>().ok();
            Ok((Some(leader), term))
        } else {
            Ok((None, None))
        }
    })
    .await
    {
        Ok(Ok((leader, term))) => ConsensusStatus {
            healthy: leader.is_some(),
            leader,
            term,
            error: None,
        },
        Ok(Err(e)) => ConsensusStatus {
            healthy: false,
            leader: None,
            term: None,
            error: Some(e.to_string()),
        },
        Err(e) => ConsensusStatus {
            healthy: false,
            leader: None,
            term: None,
            error: Some(format!("Task failed: {e}")),
        },
    }
}

async fn check_system_health(ssh: &SshSession) -> SystemStatus {
    let ssh = ssh.clone();

    match tokio::task::spawn_blocking(move || {
        // Check memory
        let mem_output = ssh.exec("free -m | grep Mem").unwrap_or_default();
        let memory_percent = parse_memory_usage(&mem_output);

        // Check disk
        let disk_output = ssh
            .exec("df -h /var/makiatto | tail -1")
            .unwrap_or_default();
        let disk_percent = parse_disk_usage(&disk_output);

        // Check load
        let load_output = ssh.exec("uptime").unwrap_or_default();
        let load_average = parse_load_average(&load_output);

        Ok::<_, miette::Error>((memory_percent, disk_percent, load_average))
    })
    .await
    {
        Ok(Ok((memory, disk, load))) => {
            let healthy = memory.is_none_or(|m| m < 90.0)
                && disk.is_none_or(|d| d < 90.0)
                && load.is_none_or(|l| l < 4.0);

            SystemStatus {
                healthy,
                memory_percent: memory,
                disk_percent: disk,
                load_average: load,
                error: None,
            }
        }
        Ok(Err(e)) => SystemStatus {
            healthy: false,
            memory_percent: None,
            disk_percent: None,
            load_average: None,
            error: Some(e.to_string()),
        },
        Err(e) => SystemStatus {
            healthy: false,
            memory_percent: None,
            disk_percent: None,
            load_average: None,
            error: Some(format!("Task failed: {e}")),
        },
    }
}

fn parse_memory_usage(output: &str) -> Option<f64> {
    let parts: Vec<&str> = output.split_whitespace().collect();
    if parts.len() >= 3 {
        let total = parts[1].parse::<f64>().ok()?;
        let available = parts
            .get(6)
            .and_then(|s| s.parse::<f64>().ok())
            .or_else(|| parts.get(3).and_then(|s| s.parse::<f64>().ok()))?;

        if total > 0.0 {
            Some(((total - available) / total) * 100.0)
        } else {
            None
        }
    } else {
        None
    }
}

fn parse_disk_usage(output: &str) -> Option<f64> {
    let parts: Vec<&str> = output.split_whitespace().collect();
    if parts.len() >= 5 {
        parts[4].trim_end_matches('%').parse::<f64>().ok()
    } else {
        None
    }
}

fn parse_load_average(output: &str) -> Option<f64> {
    if let Some(idx) = output.find("load average:") {
        let load_str = &output[idx + 13..];
        let parts: Vec<&str> = load_str.split(',').collect();
        if parts.is_empty() {
            None
        } else {
            parts[0].trim().parse::<f64>().ok()
        }
    } else {
        None
    }
}

async fn check_dns_health(machine: &Machine, config: &Config) -> DnsStatus {
    let ip: IpAddr = machine
        .ipv4
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

    let sock_addr = SocketAddr::new(ip, 53);

    let nameserver = NameServerConfig::new(sock_addr, Protocol::Udp);

    let mut resolver_config = ResolverConfig::new();
    resolver_config.add_name_server(nameserver);

    let resolver =
        TokioResolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
            .build();

    let test_domain = config
        .domains
        .first()
        .map_or("invalid.domain", |d| d.name.as_ref());

    match timeout(Duration::from_secs(5), resolver.lookup_ip(test_domain)).await {
        Ok(Ok(_)) => DnsStatus {
            healthy: true,
            error: None,
        },
        Ok(Err(e)) => DnsStatus {
            healthy: false,
            error: Some(format!("DNS query failed: {e}")),
        },
        Err(_) => DnsStatus {
            healthy: false,
            error: Some("DNS query timeout".to_string()),
        },
    }
}

async fn check_web_domains(
    machine: &Machine,
    config: &Config,
    certificates: &HashMap<String, i64>,
) -> Vec<DomainStatus> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let mut domain_futures = Vec::new();

    for domain in config.domains.iter() {
        let domain_name = domain.name.as_ref();
        let cert_info = certificates.get(domain_name);

        domain_futures.push(check_single_domain(
            &client,
            machine,
            domain_name,
            cert_info,
        ));

        // also check aliases
        for alias in domain.aliases.iter() {
            let alias_name = alias.as_ref();
            let cert_info = certificates.get(alias_name);

            domain_futures.push(check_single_domain(&client, machine, alias_name, cert_info));
        }
    }

    join_all(domain_futures).await
}

async fn check_single_domain(
    client: &reqwest::Client,
    machine: &Machine,
    domain: &str,
    cert_expires_at: Option<&i64>,
) -> DomainStatus {
    // calculate certificate days remaining if we have cert info
    let cert_days = cert_expires_at.as_ref().and_then(|cert| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let now_i64 = i64::try_from(now).ok()?;
        Some((*cert - now_i64) / 86400)
    });

    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_str(domain).unwrap());

    let (is_https, url) = if cert_expires_at.is_some() {
        (true, format!("https://{}", machine.ipv4))
    } else {
        (false, format!("http://{}", machine.ipv4))
    };

    match timeout(
        Duration::from_secs(5),
        client.get(&url).headers(headers).send(),
    )
    .await
    {
        Ok(Ok(response)) if response.status().is_success() => DomainStatus {
            domain: domain.into(),
            healthy: true,
            is_https,
            cert_days_remaining: cert_days,
            error: None,
        },
        Ok(Ok(response)) => DomainStatus {
            domain: domain.into(),
            healthy: false,
            is_https,
            cert_days_remaining: cert_days,
            error: Some(format!("HTTP {}", response.status())),
        },
        Ok(Err(e)) => DomainStatus {
            domain: domain.into(),
            healthy: false,
            is_https,
            cert_days_remaining: cert_days,
            error: Some(e.to_string()),
        },
        Err(_) => DomainStatus {
            domain: domain.into(),
            healthy: false,
            is_https,
            cert_days_remaining: cert_days,
            error: Some("Request timeout".to_string()),
        },
    }
}

fn check_consensus_agreement(results: &[NodeHealth]) -> bool {
    let mut leaders = HashMap::new();
    let mut terms = HashMap::new();
    let mut healthy_count = 0;

    for node in results {
        if node.consensus.healthy {
            healthy_count += 1;
            if let Some(ref leader) = node.consensus.leader {
                *leaders.entry(leader.clone()).or_insert(0) += 1;
            }
            if let Some(term) = node.consensus.term {
                *terms.entry(term).or_insert(0) += 1;
            }
        }
    }

    // all nodes must be healthy and agree on the same leader and term
    healthy_count == results.len() && leaders.len() <= 1 && terms.len() <= 1 && !leaders.is_empty()
}

#[allow(clippy::too_many_lines)]
fn display_health_results(results: &[NodeHealth], consensus_ok: bool) {
    ui::separator();

    if let Some(first_healthy) = results.iter().find(|n| n.consensus.leader.is_some()) {
        let leader = first_healthy
            .consensus
            .leader
            .as_ref()
            .map_or("Unknown", |s| s.as_str());

        let term = first_healthy.consensus.term.unwrap_or(0);

        let consensus_symbol = if consensus_ok {
            style("✓").green()
        } else {
            style("✗").red()
        };

        ui::header("Cluster Consensus");
        ui::field("Status", &format!("{consensus_symbol}"));
        ui::field("Leader", leader);
        ui::field("Term", &term.to_string());
    } else {
        let unreachable_nodes = results.iter().filter(|n| !n.consensus.healthy).count();
        let status_message = if unreachable_nodes > 0 {
            format!(
                "{} Unhealthy ({} nodes unreachable)",
                style("✗").red(),
                unreachable_nodes
            )
        } else {
            format!("{} No leader elected", style("✗").red())
        };

        ui::header("Cluster Consensus");
        ui::field("Status", &status_message);

        for node in results {
            if !node.consensus.healthy
                && let Some(ref error) = node.consensus.error
            {
                ui::field(&format!("{} error", node.name), error);
            }
        }
    }

    let mut all_domains = std::collections::HashSet::new();
    for node in results {
        for domain_status in &node.web {
            all_domains.insert(domain_status.domain.clone());
        }
    }

    if !all_domains.is_empty() {
        println!();
        ui::header("HTTP(S)");
        for domain in &all_domains {
            ui::info(domain);
            for node in results {
                if let Some(domain_status) = node.web.iter().find(|d| d.domain == *domain) {
                    let protocol = if domain_status.is_https {
                        "HTTPS"
                    } else {
                        "HTTP"
                    };

                    let mut info = protocol.to_string();
                    if let Some(days) = domain_status.cert_days_remaining {
                        if days < 30 {
                            write!(info, " (cert: {days} days - expiring soon)").unwrap();
                        } else {
                            write!(info, " (cert: {days} days)").unwrap();
                        }
                    }
                    if let Some(ref error) = domain_status.error {
                        write!(info, " - {error}").unwrap();
                    }

                    let status_symbol = if domain_status.healthy {
                        style("✓").green()
                    } else {
                        style("✗").red()
                    };
                    ui::field(
                        &format!("├─ {}", node.name),
                        &format!("{status_symbol} {info}"),
                    );
                }
            }
        }
    }

    let dns_servers: Vec<_> = results.iter().filter(|n| n.dns.is_some()).collect();
    if !dns_servers.is_empty() {
        println!();
        ui::header("DNS");
        for node in dns_servers {
            let dns = node.dns.as_ref().unwrap();
            let info = if dns.healthy {
                "Responding"
            } else {
                dns.error.as_deref().unwrap_or("Not responding")
            };
            let dns_symbol = if dns.healthy {
                style("✓").green()
            } else {
                style("✗").red()
            };
            ui::field(
                &format!("├─ {}", node.name),
                &format!("{dns_symbol} {info}"),
            );
        }
    }

    println!();
    ui::header("System Resources");
    for node in results {
        let mut info = Vec::new();
        if let Some(mem) = node.system.memory_percent {
            info.push(format!("Mem: {mem:.1}%"));
        }
        if let Some(disk) = node.system.disk_percent {
            info.push(format!("Disk: {disk:.1}%"));
        }
        if let Some(load) = node.system.load_average {
            info.push(format!("Load: {load:.2}"));
        }

        if info.is_empty() && node.system.error.is_some() {
            ui::field(
                &format!("├─ {}", node.name),
                &format!(
                    "{} {}",
                    style("✗").red(),
                    node.system.error.as_ref().unwrap()
                ),
            );
        } else {
            let system_symbol = if node.system.healthy {
                style("✓").green()
            } else {
                style("⚠").yellow()
            };
            ui::field(
                &format!("├─ {}", node.name),
                &format!("{system_symbol} {}", info.join(", ")),
            );
        }
    }
}
