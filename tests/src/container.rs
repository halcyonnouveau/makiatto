#![cfg(test)]
use std::{
    collections::HashSet,
    env,
    net::TcpListener,
    path,
    process::Command,
    sync::{Arc, Mutex, OnceLock},
};

use base64::prelude::*;
use makiatto_cli::config::Machine;
use miette::{Result, miette};
use rand::{Rng, distr::Alphanumeric};
use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
};

static PORT_REGISTRY: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();

fn get_port_registry() -> &'static Mutex<HashSet<u16>> {
    PORT_REGISTRY.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(Clone, PartialEq)]
pub enum Image {
    Base,
    Daemon,
}

pub struct ContainerContext {
    pub gateway_ip: Arc<str>,
    pub root: path::PathBuf,
    pub target: path::PathBuf,
    containers: Vec<TestContainer>,
}

impl ContainerContext {
    pub fn new() -> Result<Self> {
        let id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();

        let cwd = env::var("CARGO_MANIFEST_DIR").unwrap();
        let root = path::Path::new(&cwd).parent().unwrap();
        let target = root.join(format!("target/tests/context-{id}"));

        Self::ensure_wawa_network()?;

        Ok(Self {
            gateway_ip: Arc::from(Self::get_gateway_ip()?),
            root: root.to_owned(),
            target,
            containers: Vec::new(),
        })
    }

    fn ensure_wawa_network() -> Result<()> {
        let check_output = Command::new("docker")
            .args([
                "network",
                "ls",
                "--filter",
                "name=wawa",
                "--format",
                "{{.Name}}",
            ])
            .output()
            .map_err(|e| miette!("Failed to check for wawa network: {e}"))?;

        let networks = String::from_utf8_lossy(&check_output.stdout);
        if networks.trim() == "wawa" {
            return Ok(());
        }

        let create_output = Command::new("docker")
            .args(["network", "create", "wawa"])
            .output()
            .map_err(|e| miette!("Failed to create wawa network: {e}"))?;

        if !create_output.status.success() {
            let stderr = String::from_utf8_lossy(&create_output.stderr);
            if stderr.contains("already exists") {
                return Ok(());
            }
            return Err(miette!("Failed to create wawa network: {stderr}"));
        }

        Ok(())
    }

    fn get_gateway_ip() -> Result<String> {
        let output = Command::new("sh")
            .args([
                "-c",
                "docker network inspect wawa | grep -i gateway | head -1 | cut -f 4 -d '\"'",
            ])
            .output()
            .map_err(|e| miette::miette!("Failed to get wawa network gateway: {e}"))?;

        if !output.status.success() {
            return Err(miette::miette!("Failed to inspect wawa network"));
        }

        let gateway = String::from_utf8(output.stdout)
            .map_err(|e| miette::miette!("Invalid UTF-8 in gateway output: {e}"))?
            .trim()
            .to_string();

        if gateway.is_empty() {
            return Err(miette::miette!("No gateway found for wawa network"));
        }

        Ok(gateway)
    }

    pub async fn make_base(&mut self) -> Result<TestContainer> {
        let mut container = TestContainer::new(Image::Base)?;

        let image = GenericImage::new("makiatto-test-ubuntu_base", "latest")
            .with_exposed_port(22.tcp())
            .with_exposed_port(8787.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_container_name(format!("{}-wawa-base", container.id))
            .with_mapped_port(container.ports.ssh, 22.tcp())
            .with_mapped_port(container.ports.corrosion, 8787.tcp())
            .with_network("wawa");

        container.start_image(image).await?;
        self.containers.push(container.clone());

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        Ok(container)
    }

    pub async fn make_daemon(&mut self) -> Result<TestContainer> {
        let mut container = TestContainer::new(Image::Daemon)?;
        let target = self.target.join(format!("container-{}", container.id));

        tokio::fs::create_dir_all(&target)
            .await
            .map_err(|e| miette::miette!("Failed to create directory: {e}"))?;

        tokio::fs::copy(
            self.root.join("tests/fixtures/makiatto.toml"),
            target.join("makiatto.toml"),
        )
        .await
        .map_err(|e| miette::miette!("Failed to copy makiatto.toml: {e}"))?;

        Self::replace(
            "name = \"wawa-daemon\"",
            &format!("name = \"{}-wawa-daemon\"", container.id),
            &target.join("makiatto.toml"),
        )
        .await?;

        Self::replace(
            "external_addr = \"127.0.0.1:8787\"",
            &format!(
                "external_addr = \"{}:{}\"",
                self.gateway_ip, container.ports.corrosion
            ),
            &target.join("makiatto.toml"),
        )
        .await?;

        let prev_corro_ports: Vec<u16> = self
            .containers
            .iter()
            .filter_map(|c| {
                if c.image == Image::Daemon {
                    Some(c.ports.corrosion)
                } else {
                    None
                }
            })
            .collect();

        if !prev_corro_ports.is_empty() {
            let bootstrap: String = prev_corro_ports
                .iter()
                .map(|port| format!("\"{}:{port}\"", self.gateway_ip))
                .collect::<Vec<_>>()
                .join(", ");

            Self::replace(
                "bootstrap = []",
                &format!("bootstrap = [{bootstrap}]"),
                &target.join("makiatto.toml"),
            )
            .await?;
        }

        let image = GenericImage::new("makiatto-test-ubuntu_daemon", "latest")
            .with_exposed_port(22.tcp())
            .with_exposed_port(53.tcp())
            .with_exposed_port(53.udp())
            .with_exposed_port(853.tcp())
            .with_exposed_port(853.udp())
            .with_exposed_port(80.tcp())
            .with_exposed_port(443.tcp())
            .with_exposed_port(8787.udp())
            .with_exposed_port(8282.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_container_name(format!("{}-wawa-daemon", container.id))
            .with_mapped_port(container.ports.ssh, 22.tcp())
            .with_mapped_port(container.ports.dns, 53.tcp())
            .with_mapped_port(container.ports.dns, 53.udp())
            .with_mapped_port(container.ports.dnss, 853.tcp())
            .with_mapped_port(container.ports.dnss, 853.udp())
            .with_mapped_port(container.ports.http, 80.tcp())
            .with_mapped_port(container.ports.https, 443.tcp())
            .with_mapped_port(container.ports.corrosion, 8787.udp())
            .with_mapped_port(container.ports.fs, 8282.tcp())
            .with_network("wawa")
            .with_mount(Mount::bind_mount(
                self.root.join("target/tests/geolite").display().to_string(),
                "/var/makiatto/geolite",
            ))
            .with_mount(Mount::bind_mount(
                target.display().to_string(),
                "/etc/makiatto",
            ));

        container.start_image(image).await?;
        self.containers.push(container.clone());

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        Ok(container)
    }

    /// replace a string in a file
    async fn replace(pattern: &str, replacement: &str, path: &path::Path) -> Result<()> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| miette::miette!("Failed to read file: {e}"))?;

        let new_content = content.replace(pattern, replacement);

        tokio::fs::write(path, new_content)
            .await
            .map_err(|e| miette::miette!("Failed to write file: {e}"))?;

        Ok(())
    }
}

impl Drop for ContainerContext {
    fn drop(&mut self) {
        if self.target.exists() {
            if let Err(e) = std::fs::remove_dir_all(&self.target) {
                eprintln!(
                    "Warning: Failed to clean up test data directory {}: {e}",
                    self.target.display(),
                );
            } else {
                eprintln!("Cleaned up test directory: {}", self.target.display());
            }
        }
    }
}

#[derive(Clone)]
pub struct TestContainer {
    pub id: Arc<str>,
    pub container: Option<Arc<ContainerAsync<GenericImage>>>,
    pub image: Image,
    pub ports: PortMap,
}

impl TestContainer {
    pub fn new(image: Image) -> Result<Self> {
        let id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();

        let ports = PortMap::new()?;

        Ok(Self {
            id: Arc::from(id),
            container: None,
            image,
            ports,
        })
    }

    pub async fn start_image(&mut self, image: ContainerRequest<GenericImage>) -> Result<()> {
        let container = Arc::from(
            image
                .start()
                .await
                .map_err(|e| miette!("Failed to start image: {e}"))?,
        );
        self.container = Some(container);
        Ok(())
    }

    pub fn get_config(&self) -> Machine {
        Machine {
            name: Arc::from(format!("{}-wawa-daemon", self.id)),
            ssh_target: Arc::from(format!("root@127.0.0.1:{}", self.ports.ssh)),
            is_nameserver: true,
            wg_public_key: Arc::from("todayiwantedtoeataquaso"),
            wg_address: Arc::from("0.0.0.0"),
            latitude: Some(69.1337),
            longitude: Some(69.1337),
            ipv4: Arc::from("127.0.0.1"),
            ipv6: None,
            sync_target: true,
        }
    }
}

#[derive(Clone)]
pub struct PortMap {
    pub ssh: u16,
    pub dns: u16,
    pub dnss: u16,
    pub corrosion: u16,
    pub http: u16,
    pub https: u16,
    pub fs: u16,
}

impl PortMap {
    pub fn new() -> Result<Self> {
        Ok(Self {
            ssh: Self::get_unused_port()?,
            dns: Self::get_unused_port()?,
            dnss: Self::get_unused_port()?,
            corrosion: Self::get_unused_port()?,
            http: Self::get_unused_port()?,
            https: Self::get_unused_port()?,
            fs: Self::get_unused_port()?,
        })
    }

    fn get_unused_port() -> Result<u16> {
        let mut registry = get_port_registry()
            .lock()
            .map_err(|_| miette::miette!("Failed to acquire port registry lock"))?;

        let mut rng = rand::rng();

        for _ in 0..100 {
            let port = rng.random_range(49152..=65535);

            if registry.contains(&port) {
                continue;
            }

            if TcpListener::bind(("127.0.0.1", port)).is_ok()
                && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
            {
                registry.insert(port);
                return Ok(port);
            }
        }

        Err(miette::miette!(
            "No unused ports available after 100 attempts"
        ))
    }

    /// Release all allocated ports back to the pool
    fn release_ports(&self) {
        if let Ok(mut registry) = get_port_registry().lock() {
            registry.remove(&self.ssh);
            registry.remove(&self.dns);
            registry.remove(&self.dnss);
            registry.remove(&self.corrosion);
            registry.remove(&self.http);
            registry.remove(&self.https);
            registry.remove(&self.fs);
        }
    }
}

impl Drop for PortMap {
    fn drop(&mut self) {
        self.release_ports();
    }
}

pub mod util {
    use super::*;

    /// Helper function to execute a command in a docker container
    pub async fn execute_command(
        daemon: &Arc<ContainerAsync<GenericImage>>,
        cmd: &str,
    ) -> Result<(String, String)> {
        let mut result = daemon
            .exec(ExecCommand::new(vec!["sh", "-c", cmd]))
            .await
            .map_err(|e| miette!("Failed to execute command '{cmd}': {e}"))?;

        let stdout = result
            .stdout_to_vec()
            .await
            .map_err(|e| miette!("Failed to get stdout: {e}"))?;

        let stderr = result
            .stderr_to_vec()
            .await
            .map_err(|e| miette!("Failed to get stderr: {e}"))?;

        let stdout_str = String::from_utf8_lossy(&stdout).to_string();
        let stderr_str = String::from_utf8_lossy(&stderr).to_string();

        Ok((stdout_str, stderr_str))
    }

    /// Helper function to execute a list of commands
    pub async fn execute_commands(
        daemon: &Arc<ContainerAsync<GenericImage>>,
        commands: &[&str],
    ) -> Result<()> {
        for cmd in commands {
            let _ = execute_command(daemon, cmd).await?;
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        Ok(())
    }

    /// Helper function to generate and insert a certificate for a domain
    pub async fn generate_tls_certificate(
        daemon: &Arc<ContainerAsync<GenericImage>>,
        domain: &str,
        cert_filename: &str,
        key_filename: &str,
    ) -> Result<()> {
        daemon
            .exec(ExecCommand::new(vec!["sudo", "mkdir", "-p", "/tmp/certs"]))
            .await
            .map_err(|e| miette!("Failed to create cert directory: {e}"))?;

        let openssl_cmd = format!(
            "sudo openssl req -x509 -newkey rsa:2048 -keyout /tmp/certs/{key_filename} -out /tmp/certs/{cert_filename} -days 1 -nodes -subj '/CN={domain}'",
        );

        let mut result = daemon
            .exec(ExecCommand::new(vec!["sh", "-c", &openssl_cmd]))
            .await
            .map_err(|e| miette!("Failed to execute openssl command: {e}"))?;

        let stderr = result.stderr_to_vec().await.unwrap_or_default();
        if !stderr.is_empty() {
            let stderr_str = String::from_utf8_lossy(&stderr);
            if stderr_str.contains("error") || stderr_str.contains("Error") {
                return Err(miette::miette!("OpenSSL command failed: {}", stderr_str));
            }
        }

        // Verify certificate files exist
        let cert_check = daemon
            .exec(ExecCommand::new(vec![
                "test",
                "-f",
                &format!("/tmp/certs/{cert_filename}"),
            ]))
            .await;
        let key_check = daemon
            .exec(ExecCommand::new(vec![
                "test",
                "-f",
                &format!("/tmp/certs/{key_filename}"),
            ]))
            .await;

        if cert_check.is_err() || key_check.is_err() {
            return Err(miette::miette!(
                "Certificate files were not created properly"
            ));
        }

        // Read certificate and key files
        let mut cert_result = daemon
            .exec(ExecCommand::new(vec![
                "cat",
                &format!("/tmp/certs/{cert_filename}"),
            ]))
            .await
            .map_err(|e| miette!("Failed to read cert: {e}"))?;

        let mut key_result = daemon
            .exec(ExecCommand::new(vec![
                "cat",
                &format!("/tmp/certs/{key_filename}"),
            ]))
            .await
            .map_err(|e| miette!("Failed to read key: {e}"))?;

        let cert_bytes = cert_result.stdout_to_vec().await.unwrap();
        let key_bytes = key_result.stdout_to_vec().await.unwrap();
        let cert_pem = String::from_utf8_lossy(&cert_bytes).trim().to_string();
        let key_pem = String::from_utf8_lossy(&key_bytes).trim().to_string();

        // Validate certificate format
        if !cert_pem.starts_with("-----BEGIN CERTIFICATE-----") {
            return Err(miette::miette!("Invalid certificate format"));
        }
        if !key_pem.starts_with("-----BEGIN PRIVATE KEY-----")
            && !key_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----")
        {
            return Err(miette::miette!("Invalid private key format"));
        }

        let cert_b64 = BASE64_STANDARD.encode(cert_pem.as_bytes());
        let key_b64 = BASE64_STANDARD.encode(key_pem.as_bytes());

        // Insert certificate into database
        let cert_sql = format!(
            "INSERT INTO certificates (domain, certificate_pem, private_key_pem, expires_at, issuer) VALUES ('{domain}', '{cert_b64}', '{key_b64}', {}, 'test')",
            jiff::Timestamp::now().as_second() + 86400
        );

        let json_payload = serde_json::to_string(&[cert_sql]).unwrap();

        let mut insert_result = daemon
            .exec(ExecCommand::new(vec![
                "curl",
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &json_payload,
                "http://127.0.0.1:8181/v1/transactions",
            ]))
            .await
            .map_err(|e| miette!("Failed to insert certificate: {e}"))?;

        let insert_bytes = insert_result.stdout_to_vec().await.unwrap();
        let response = String::from_utf8_lossy(&insert_bytes);
        if !response.contains("\"rows_affected\"") || response.contains("\"error\"") {
            return Err(miette!("Certificate insertion failed: {}", response));
        }

        Ok(())
    }

    /// Execute a Corrosion transaction (SQL insert/update/delete)
    pub async fn execute_transaction(
        daemon: &Arc<ContainerAsync<GenericImage>>,
        sql: &str,
    ) -> Result<()> {
        let json_payload = format!("[\"{sql}\"]");

        let mut result = daemon
            .exec(ExecCommand::new(vec![
                "curl",
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &json_payload,
                "http://127.0.0.1:8181/v1/transactions",
            ]))
            .await
            .map_err(|e| miette!("Failed to execute transaction: {e}"))?;

        let response_bytes = result.stdout_to_vec().await.unwrap();
        let response = String::from_utf8_lossy(&response_bytes);
        if !response.contains("\"rows_affected\"") || response.contains("\"error\"") {
            return Err(miette!("Transaction failed: {}", response));
        }

        Ok(())
    }

    /// Execute a `SQLite` query against the cluster database
    pub async fn query_database(
        daemon: &Arc<ContainerAsync<GenericImage>>,
        sql: &str,
    ) -> Result<String> {
        let mut result = daemon
            .exec(ExecCommand::new(vec![
                "sqlite3",
                "/var/makiatto/cluster.db",
                sql,
            ]))
            .await
            .map_err(|e| miette!("Failed to query database: {e}"))?;

        let response_bytes = result.stdout_to_vec().await.unwrap();
        Ok(String::from_utf8_lossy(&response_bytes).to_string())
    }

    /// Get current timestamp as seconds since UNIX epoch
    #[allow(clippy::cast_possible_wrap)]
    pub fn current_timestamp() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Insert a DNS record via Corrosion API
    pub async fn insert_dns_record(
        daemon: &Arc<ContainerAsync<GenericImage>>,
        domain: &str,
        record_type: &str,
        value: &str,
    ) -> Result<()> {
        let name = domain.split('.').next().unwrap_or(domain);
        let sql = format!(
            r"INSERT INTO dns_records (domain, name, record_type, value, source_domain, ttl, priority, geo_enabled) VALUES ('{domain}', '{name}', '{record_type}', '{value}', '{domain}', 300, 0, 0)"
        );
        execute_transaction(daemon, &sql).await
    }

    /// Insert a certificate via Corrosion API
    pub async fn insert_certificate_record(
        daemon: &Arc<ContainerAsync<GenericImage>>,
        domain: &str,
        expires_in_days: i64,
    ) -> Result<()> {
        let current_time = current_timestamp();
        let expires_at = current_time + (expires_in_days * 86400);

        let certificate_pem = format!(
            "-----BEGIN CERTIFICATE-----\\ntest_cert_for_{domain}\\n-----END CERTIFICATE-----"
        );
        let private_key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\\ntest_key_for_{domain}\\n-----END PRIVATE KEY-----"
        );

        let sql = format!(
            "INSERT INTO certificates (domain, certificate_pem, private_key_pem, expires_at, issuer) VALUES ('{domain}', '{certificate_pem}', '{private_key_pem}', {expires_at}, 'test_ca')"
        );
        execute_transaction(daemon, &sql).await
    }

    /// Insert certificate renewal status via Corrosion API
    pub async fn insert_renewal_status(
        daemon: &Arc<ContainerAsync<GenericImage>>,
        domain: &str,
        status: &str,
        retry_count: u32,
    ) -> Result<()> {
        let current_time = current_timestamp();

        let sql = format!(
            "INSERT INTO certificate_renewals (domain, last_check, renewal_status, next_check, retry_count, last_renewal) VALUES ('{}', {}, '{}', {}, {}, {})",
            domain,
            current_time,
            status,
            current_time + 3600,
            retry_count,
            current_time
        );
        execute_transaction(daemon, &sql).await
    }
}
