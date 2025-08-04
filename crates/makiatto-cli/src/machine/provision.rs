use std::{path::PathBuf, sync::Arc};

use indoc::formatdoc;
use miette::Result;
use serde_json::{self, Value};

use crate::{
    config::{Machine, Profile},
    r#const::{CORROSION_API_PORT, CORROSION_GOSSIP_PORT, WIREGUARD_PORT},
    machine::corrosion,
    ssh::SshSession,
    ui,
};

struct GeoData {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub ipv4: Arc<str>,
    pub ipv6: Option<Arc<str>>,
}

pub fn install_makiatto(
    mut machine: Machine,
    profile: &Profile,
    wg_private_key: &str,
    binary_path: Option<&PathBuf>,
    key_path: Option<&PathBuf>,
) -> Result<(SshSession, Machine)> {
    ui::status("Connecting to remote machine via SSH...");
    let ssh = SshSession::new(&machine.ssh_target, machine.port, key_path)?;

    let geo_data = retrieve_geolocation(&ssh)?;

    machine.ipv4 = geo_data.ipv4;
    machine.ipv6 = geo_data.ipv6;
    machine.latitude = geo_data.latitude;
    machine.longitude = geo_data.longitude;

    create_makiatto_user(&ssh)?;
    install_makiatto_binary(&ssh, binary_path)?;
    setup_system_permissions(&ssh)?;
    ensure_installed(&ssh)?;
    create_daemon_config(&ssh, profile, &machine, wg_private_key)?;

    if ssh.is_container() {
        ui::info("Container environment detected - starting makiatto as background process");
        start_makiatto_background(&ssh)?;
    } else {
        setup_systemd_service(&ssh)?;
        setup_dns_configuration(&ssh, &machine)?;
        start_makiatto_service(&ssh)?;
    }

    add_self_as_peer(&ssh, &machine)?;

    Ok((ssh, machine))
}

fn create_makiatto_user(ssh: &SshSession) -> Result<()> {
    ui::status("Creating makiatto user...");

    if ssh.exec("id makiatto").is_ok() {
        ui::info("Makiatto user already exists");
        return Ok(());
    }

    ui::action("Creating system user");
    ssh.exec(
        "sudo useradd --system --home-dir /var/makiatto --create-home --shell /bin/false makiatto",
    )?;

    ui::action("Adding user to systemd-journal group");
    ssh.exec("sudo usermod -a -G systemd-journal makiatto")?;

    ui::action("Setting up passwordless sudo permissions");
    let sudoers_cmd = formatdoc! {r"
        sudo tee /etc/sudoers.d/makiatto > /dev/null << 'EOF'
        makiatto ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/sbin/setcap, /usr/bin/mkdir, /usr/bin/chown, /usr/bin/chmod, /usr/bin/ip, /usr/sbin/ip
        EOF
    "};
    ssh.exec(&sudoers_cmd)?;

    Ok(())
}

pub fn install_makiatto_binary(ssh: &SshSession, binary_path: Option<&PathBuf>) -> Result<()> {
    ui::status("Installing makiatto binary...");

    if let Some(path) = binary_path {
        ssh.upload_file(path, "/tmp/makiatto")?;

        let commands = vec![
            "sudo mkdir -p /usr/local/bin",
            "sudo mv /tmp/makiatto /usr/local/bin/makiatto",
            "sudo chmod +x /usr/local/bin/makiatto",
            "sudo chown makiatto:makiatto /usr/local/bin/makiatto",
        ];

        for cmd in commands {
            ssh.exec(cmd)?;
        }
    } else {
        let arch_output = ssh.exec("uname -m")?;

        let target = match arch_output.trim() {
            "x86_64" => "x86_64-unknown-linux-gnu",
            "aarch64" => "aarch64-unknown-linux-gnu",
            arch => return Err(miette::miette!("Unsupported architecture: {arch}")),
        };

        let version = env!("CARGO_PKG_VERSION");
        ui::action(&format!("Downloading makiatto v{version} from GitHub..."));

        let download_url = format!(
            "https://github.com/halcyonnouveau/makiatto/releases/download/v{version}/makiatto-{target}.tar.gz",
        );

        let download_cmd = format!("curl -L -o /tmp/makiatto.tar.gz '{download_url}'");

        ssh.exec(&download_cmd)?;

        ui::action("Extracting and installing binary...");
        let commands = vec![
            "cd /tmp && tar -xzf makiatto.tar.gz",
            "sudo mkdir -p /usr/local/bin",
            "sudo mv /tmp/makiatto /usr/local/bin/makiatto",
            "sudo chmod +x /usr/local/bin/makiatto",
            "sudo chown makiatto:makiatto /usr/local/bin/makiatto",
            "rm -f /tmp/makiatto.tar.gz",
        ];

        for cmd in commands {
            ssh.exec(cmd)?;
        }
    }

    Ok(())
}

fn setup_system_permissions(ssh: &SshSession) -> Result<()> {
    ui::status("Setting up system permissions...");

    // only set capabilities if not in a container (overlay fs doesn't support xattrs properly)
    if ssh.is_container() {
        ui::info("Container detected - skipping capability setup (overlay fs limitation)");
    } else {
        ui::action("Setting network admin capabilities");
        ssh.exec("sudo setcap cap_net_admin=+epi /usr/local/bin/makiatto")?;
    }

    ui::action("Configuring unprivileged port binding");
    ssh.exec("sudo mkdir -p /etc/sysctl.d")?;
    ssh.exec(
        "sudo bash -c 'echo \"net.ipv4.ip_unprivileged_port_start=0\" > /etc/sysctl.d/50-unprivileged-ports.conf'"
    )?;

    ui::action("Configuring inotify limits");
    ssh.exec(
        "sudo bash -c 'echo \"fs.inotify.max_queued_events=65536\" > /etc/sysctl.d/51-inotify-limits.conf'",
    )?;
    ssh.exec(
        "sudo bash -c 'echo \"fs.inotify.max_user_watches=524288\" >> /etc/sysctl.d/51-inotify-limits.conf'"
    )?;

    ui::action("Reloading sysctl configuration");
    ssh.exec("sudo sysctl --system")?;

    Ok(())
}

fn ensure_installed(ssh: &SshSession) -> Result<()> {
    let install = |binary: &str, commands: &[&str]| -> Result<()> {
        if ssh.exec(&format!("which {binary}")).is_ok() {
            return Ok(());
        }

        ui::status(&format!("Installing {binary}..."));

        for cmd in commands {
            if ssh.exec(cmd).is_ok() && ssh.exec(&format!("which {binary}")).is_ok() {
                return Ok(());
            }
        }

        Err(miette::miette!(
            "Failed to install {binary}. Please install it manually on the target system.",
        ))
    };

    install(
        "sqlite3",
        &[
            "sudo apt update && sudo apt install -y sqlite3",
            "sudo dnf install -y sqlite || sudo yum install -y sqlite",
            "sudo apk add sqlite",
            "sudo pacman -S --noconfirm sqlite",
            "sudo zypper install -y sqlite3",
            "sudo emerge dev-db/sqlite",
            "sudo pkg install -y sqlite3",
        ],
    )?;

    install(
        "rsync",
        &[
            "sudo apt update && sudo apt install -y rsync",
            "sudo dnf install -y rsync || sudo yum install -y rsync",
            "sudo apk add rsync",
            "sudo pacman -S --noconfirm rsync",
            "sudo zypper install -y rsync",
            "sudo emerge net-misc/rsync",
            "sudo pkg install -y rsync",
        ],
    )?;

    install(
        "curl",
        &[
            "sudo apt update && sudo apt install -y curl",
            "sudo dnf install -y curl || sudo yum install -y curl",
            "sudo apk add curl",
            "sudo pacman -S --noconfirm curl",
            "sudo zypper install -y curl",
        ],
    )?;

    Ok(())
}

fn setup_dns_configuration(ssh: &SshSession, machine: &Machine) -> Result<()> {
    if machine.is_nameserver {
        ui::status("Configuring DNS...");
        ui::action("Disabling systemd-resolved");
        ssh.exec("sudo systemctl disable --now systemd-resolved")?;

        ui::action("Setting up external DNS resolution");
        ssh.exec("sudo rm -f /etc/resolv.conf")?;
        ssh.exec("sudo bash -c 'echo \"nameserver 9.9.9.9\" > /etc/resolv.conf'")?;
        ssh.exec("sudo bash -c 'echo \"nameserver 1.1.1.1\" >> /etc/resolv.conf'")?;

        ui::info("Configured Quad9 (9.9.9.9) and Cloudflare (1.1.1.1) as upstream DNS");
    } else {
        ui::info("Machine is not a nameserver - keeping default DNS configuration");
    }

    Ok(())
}

fn create_daemon_config(
    ssh: &SshSession,
    profile: &Profile,
    machine: &Machine,
    wg_private_key: &str,
) -> Result<()> {
    ui::status("Creating makiatto configuration...");

    // bootstrap with wireguard ip address + corrosion gossip port
    let corrosion_bootstrap: Vec<String> = profile
        .machines
        .iter()
        .take(10)
        .filter(|m| m.name != machine.name)
        .map(|m| format!("{}:{CORROSION_GOSSIP_PORT}", m.wg_address))
        .collect();

    // collect wireguard bootstrap peers
    let wireguard_peers: Vec<String> = profile
        .machines
        .iter()
        .map(|m| {
            formatdoc! {r#"
            [[wireguard.bootstrap]]
            endpoint = "{}:{WIREGUARD_PORT}"
            address = "{}"
            public_key = "{}""#,
            m.ipv4,
            m.wg_address,
            m.wg_public_key,
            }
        })
        .collect();

    let config_content = formatdoc! {
        r#"
        [node]
        name = "{name}"
        data_dir = "/var/makiatto"
        is_nameserver = {is_nameserver}

        [wireguard]
        interface = "wawa0"
        address = "{wg_address}"
        private_key = "{wg_private_key}"
        public_key = "{wg_public_key}"

        {wireguard_bootstrap}

        [dns]
        geolite_path = "/var/makiatto/geolite/GeoLite2-City.mmdb"

        [web]
        http_addr = "0.0.0.0:80"
        https_addr = "0.0.0.0:443"
        static_dir = "/var/makiatto/sites"

        [corrosion.admin]
        path = "/var/makiatto/admin.sock"

        [corrosion.db]
        path = "/var/makiatto/cluster.db"

        [corrosion.gossip]
        addr = "{wg_address}:{corrosion_gossip_port}"
        external_addr = "{wg_address}:{corrosion_gossip_port}"
        bootstrap = {corrosion_bootstrap:?}
        plaintext = true

        [corrosion.api]
        addr = "127.0.0.1:{corrosion_api_port}"
        "#,
        name = machine.name,
        is_nameserver = machine.is_nameserver,
        wg_address = if ssh.is_container() {
            "127.0.0.1".to_string() } else { machine.wg_address.to_string()
        },
        wg_private_key = wg_private_key,
        wg_public_key = machine.wg_public_key,
        wireguard_bootstrap = wireguard_peers.join("\n\n"),
        corrosion_bootstrap = corrosion_bootstrap,
        corrosion_gossip_port = CORROSION_GOSSIP_PORT,
        corrosion_api_port = CORROSION_API_PORT,
    };

    if ssh.exec("test -d /var/makiatto").is_ok() {
        ui::action("Cleaning up old data directory");
        ssh.exec("sudo rm -rf /var/makiatto")?;
    }

    ui::action("Creating data directories");
    ssh.exec("sudo mkdir -p /var/makiatto")?;
    ssh.exec("sudo mkdir -p /var/makiatto/sites")?;
    ssh.exec("sudo mkdir -p /etc/makiatto")?;

    ui::action("Setting directory ownership");
    ssh.exec("sudo chown -R makiatto:makiatto /var/makiatto")?;

    ui::action("Setting setgid bit for consistent group ownership");
    ssh.exec("sudo chmod g+s /var/makiatto")?;
    ssh.exec("sudo chmod g+s /var/makiatto/sites")?;

    ui::action("Writing configuration file");
    let write_config_cmd = formatdoc! {r"
        sudo tee /etc/makiatto.toml > /dev/null << 'EOF'
        {config_content}
        EOF
        ",
        config_content = config_content
    };
    ssh.exec(&write_config_cmd)?;
    ssh.exec("sudo chown makiatto:makiatto /etc/makiatto.toml")?;

    Ok(())
}

fn setup_systemd_service(ssh: &SshSession) -> Result<()> {
    ui::status("Setting up systemd service...");

    let service_content = formatdoc! {r"
        [Unit]
        Description=Makiatto CDN
        After=network.target
        Wants=network.target

        [Service]
        Type=simple
        ExecStart=/usr/local/bin/makiatto
        Restart=on-failure
        RestartSec=10
        StartLimitBurst=3
        User=makiatto
        Group=makiatto
        Environment=RUST_LOG=makiatto=info
        WorkingDirectory=/var/makiatto

        [Install]
        WantedBy=multi-user.target
    "};

    ui::action("Writing systemd service file");
    let write_service_cmd = formatdoc! {r"
        sudo tee /etc/systemd/system/makiatto.service > /dev/null << 'EOF'
        {service_content}
        EOF
        ",
        service_content = service_content
    };
    ssh.exec(&write_service_cmd)?;

    Ok(())
}

fn start_makiatto_service(ssh: &SshSession) -> Result<()> {
    ui::status("Starting makiatto service...");

    ui::action("Reloading systemd daemon");
    ssh.exec("sudo systemctl daemon-reload")?;

    ui::action("Enabling service on boot");
    ssh.exec("sudo systemctl enable makiatto")?;
    ssh.exec("sudo systemctl restart makiatto")?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    match ssh.exec("sudo systemctl is-active makiatto") {
        Ok(status) => {
            if status.trim() != "active" {
                return Err(miette::miette!(
                    "Service status: {} - check 'sudo systemctl status makiatto' for details",
                    status.trim(),
                ));
            }
        }
        Err(_) => {
            return Err(miette::miette!(
                "Service failed to start - check logs with 'sudo journalctl -u makiatto'"
            ));
        }
    }

    Ok(())
}

fn add_self_as_peer(ssh: &SshSession, machine: &Machine) -> Result<()> {
    ui::status("Inserting self into database...");
    let spinner = ui::spinner("Checking for waiting for database to be ready...");
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(10);

    loop {
        if start_time.elapsed() > timeout {
            spinner.finish_with_message("Timeout waiting for peers table");
            return Err(miette::miette!(
                "Timeout waiting for peers table to be created"
            ));
        }

        let result = ssh.exec("sudo -u makiatto sqlite3 /var/makiatto/cluster.db \".tables\"");

        if let Ok(output) = result
            && output.contains("peers")
        {
            spinner.finish_with_message("✓ Database ready");
            std::thread::sleep(std::time::Duration::from_secs(1));
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    ui::action("Writing to Corrosion API");
    corrosion::insert_peer(ssh, machine)?;

    Ok(())
}

fn start_makiatto_background(ssh: &SshSession) -> Result<()> {
    ui::status("Starting makiatto in background...");

    ui::action("Launching background process");
    ssh.exec("sudo -u makiatto nohup /usr/local/bin/makiatto > /var/makiatto/makiatto.log 2>&1 &")?;
    std::thread::sleep(std::time::Duration::from_secs(1));

    let result = ssh.exec("pgrep -f '/usr/local/bin/makiatto'");
    match result {
        Ok(pid) => {
            ui::info(&format!("Makiatto started with PID: {}", pid.trim()));
        }
        Err(_) => {
            return Err(miette::miette!(
                "Failed to start makiatto - check logs with 'tail /var/makiatto/makiatto.log'"
            ));
        }
    }

    Ok(())
}

fn retrieve_geolocation(ssh: &SshSession) -> Result<GeoData> {
    ui::status("Retrieving geolocation for machine...");

    let mut data = GeoData {
        ipv4: Arc::from(""),
        ipv6: None,
        latitude: None,
        longitude: None,
    };

    let version = env!("CARGO_PKG_VERSION");
    let user_agent = format!("makiatto-cli/{version} (https://github.com/halcyonnouveau/makiatto)");

    let ipv4_result = ssh.exec(&format!(
        "curl -s --connect-timeout 5 --max-time 15 -H 'User-Agent: {user_agent}' https://api4.ipify.org"
    ));

    match ipv4_result {
        Ok(ipv4) => {
            let ipv4 = ipv4.trim();
            if !ipv4.is_empty() && !ipv4.contains("error") && ipv4.contains('.') {
                ui::info(&format!("Fetched IPv4: {ipv4}"));
                data.ipv4 = Arc::from(ipv4);
            } else {
                return Err(miette::miette!("Could not fetch IPv4 address"));
            }
        }
        Err(_) => {
            return Err(miette::miette!("Could not fetch IPv4 address"));
        }
    }

    let ipv6_result = ssh.exec(&format!(
        "curl -s --connect-timeout 5 --max-time 15 -H 'User-Agent: {user_agent}' https://api6.ipify.org"
    ));

    match ipv6_result {
        Ok(ipv6) => {
            let ipv6 = ipv6.trim();
            if !ipv6.is_empty() && !ipv6.contains("error") && ipv6.contains(':') {
                ui::info(&format!("Fetched IPv6: {ipv6}"));
                data.ipv6 = Some(Arc::from(ipv6));
            }
        }
        Err(_) => {
            ui::info("Unable to fetch IPv6 address");
        }
    }

    let geo_result = ssh.exec(&format!(
        "curl -s --connect-timeout 10 --max-time 30 -H 'User-Agent: {user_agent}' https://ipapi.co/json/"
    ));

    match geo_result {
        Ok(response) => {
            if let Ok(geo_data) = serde_json::from_str::<Value>(&response)
                && let (Some(lat), Some(lon)) = (
                    geo_data.get("latitude").and_then(Value::as_f64),
                    geo_data.get("longitude").and_then(Value::as_f64),
                )
            {
                ui::info(&format!("Fetched geolocation: {lat:.4}, {lon:.4}"));
                data.latitude = Some(lat);
                data.longitude = Some(lon);
            }
        }
        Err(_) => {
            ui::info("Unable to fetched geolocation data");
        }
    }

    Ok(data)
}
