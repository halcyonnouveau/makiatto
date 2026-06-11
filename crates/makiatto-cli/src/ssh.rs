use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use miette::{Result, miette};
use ssh2::{CheckResult, HostKeyType, KnownHostFileKind, Session};

use crate::ui;

#[derive(Clone)]
pub struct SshSession {
    pub session: Session,
    pub user: String,
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    is_container: bool,
}

impl SshSession {
    /// Create a new SSH session
    ///
    /// # Errors
    /// Returns an error if connection fails or authentication fails
    pub fn new(ssh_target: &str, port: Option<u16>, key_path: Option<&PathBuf>) -> Result<Self> {
        let (user, host, parsed_port) = parse_ssh_target(ssh_target)?;
        // explicit --port wins, otherwise use a port embedded in the target, else 22
        let port = port.or(parsed_port).unwrap_or(22);

        let tcp = TcpStream::connect((host.as_str(), port))
            .map_err(|e| miette!("Failed to connect to {host}:{port}: {e}"))?;

        let mut session =
            Session::new().map_err(|e| miette!("Failed to create SSH session: {e}"))?;

        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|e| miette!("SSH handshake failed: {e}"))?;

        // verify the server's host key against ~/.ssh/known_hosts BEFORE
        // authenticating, so we never hand the sudo password / WG private key to
        // a machine-in-the-middle
        verify_host_key(&session, &host, port)?;

        if let Some(key_path) = key_path {
            if session
                .userauth_pubkey_file(&user, None, key_path, None)
                .is_ok()
            {
                ui::info(&format!(
                    "Authenticated with SSH key: {}",
                    key_path.display()
                ));
            } else {
                return Err(miette!(
                    "Failed to authenticate with provided key: {}",
                    key_path.display()
                ));
            }
        } else if session.userauth_agent(&user).is_ok() {
            ui::info("Authenticated via SSH agent");
        } else {
            let mut authenticated = false;
            for key_path in find_ssh_keys() {
                if session
                    .userauth_pubkey_file(&user, None, &key_path, None)
                    .is_ok()
                {
                    ui::info(&format!(
                        "Authenticated with SSH key: {}",
                        key_path.display()
                    ));
                    authenticated = true;
                    break;
                }
            }

            if !authenticated {
                return Err(miette!(
                    "SSH authentication failed. Please ensure you have a valid SSH key configured"
                ));
            }
        }

        let mut ssh = Self {
            session,
            user,
            host,
            port,
            password: None,
            is_container: false,
        };

        ssh.password = ssh.test_sudo()?;

        // detect container environments in all build profiles, not just debug —
        // provisioning needs this to choose the background/no-wireguard path
        ssh.is_container = ssh
            .execute_command_raw("[ -f /run/.containerenv ] || [ -f /.dockerenv ]", None)
            .is_ok();

        Ok(ssh)
    }

    /// Execute a command over SSH
    ///
    /// # Errors
    /// Returns an error if command execution fails
    ///
    /// # Panics
    /// Panics if password is expected but not available
    pub fn exec(&self, command: &str) -> Result<String> {
        if let Some(password) = &self.password
            && command.starts_with("sudo ")
        {
            return self.execute_command_with_sudo(command, password, None);
        }

        self.execute_command_raw(command, None)
    }

    /// Execute a command over SSH, streaming stdout/stderr to the terminal in real-time
    /// and forwarding stdin for interactive prompts.
    ///
    /// # Errors
    /// Returns an error if command execution fails
    pub fn exec_stream(&self, command: &str) -> Result<i32> {
        // Feed the sudo password over the (encrypted) channel stdin via `sudo -S`
        // rather than `echo '{pw}' |`, which would leak it into the remote
        // process list.
        let (command, sudo_password) = if self.password.is_some() && command.starts_with("sudo ") {
            (wrap_sudo_command(command), self.password.clone())
        } else {
            (command.to_string(), None)
        };

        let mut channel = self
            .session
            .channel_session()
            .map_err(|e| miette!("Failed to open channel: {e}"))?;

        channel
            .request_pty("xterm", None, None)
            .map_err(|e| miette!("Failed to request PTY: {e}"))?;

        channel
            .exec(&command)
            .map_err(|e| miette!("Failed to execute command: {e}"))?;

        if let Some(password) = sudo_password {
            channel
                .write_all(format!("{password}\n").as_bytes())
                .map_err(|e| miette!("Failed to send sudo password: {e}"))?;
            channel.flush().ok();
        }

        // Put local terminal into raw mode so keypresses are forwarded immediately.
        // Do this BEFORE switching the channel to non-blocking, so that if raw
        // mode fails we never leave the session stuck in non-blocking mode.
        let _raw_guard = RawModeGuard::enter()
            .map_err(|e| miette!("Failed to enable raw terminal mode: {e}"))?;

        // Set channel to non-blocking so we can interleave reads and writes
        self.session.set_blocking(false);

        let mut buf = [0u8; 4096];
        let mut stdin_buf = [0u8; 256];
        let mut stdout = std::io::stdout();
        let stdin_fd = libc::STDIN_FILENO;

        loop {
            if channel.eof() {
                break;
            }

            // Read from channel stdout and write to local stdout
            match channel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    stdout.write_all(&buf[..n]).ok();
                    stdout.flush().ok();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    self.session.set_blocking(true);
                    return Err(miette!("Failed to read from channel: {e}"));
                }
            }

            // Check if stdin has data available (non-blocking via poll)
            let mut pollfd = libc::pollfd {
                fd: stdin_fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let poll_result = unsafe { libc::poll(&raw mut pollfd, 1, 0) };

            if poll_result > 0 && (pollfd.revents & libc::POLLIN) != 0 {
                let n =
                    unsafe { libc::read(stdin_fd, stdin_buf.as_mut_ptr().cast(), stdin_buf.len()) };

                if n > 0 {
                    #[allow(clippy::cast_sign_loss)]
                    channel.write_all(&stdin_buf[..n as usize]).ok();
                    channel.flush().ok();
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        self.session.set_blocking(true);

        channel.wait_close().ok();
        let exit_status = channel.exit_status().unwrap_or(-1);

        Ok(exit_status)
    }

    #[allow(dead_code)]
    /// Execute a command over SSH with timeout
    ///
    /// # Errors
    /// Returns an error if command execution fails or times out
    ///
    /// # Panics
    /// Panics if password is expected but not available
    pub fn exec_timeout(&self, command: &str, timeout: Duration) -> Result<String> {
        if let Some(password) = &self.password
            && command.starts_with("sudo ")
        {
            return self.execute_command_with_sudo(command, password, Some(timeout));
        }

        self.execute_command_raw(command, Some(timeout))
    }

    /// Upload a file via SCP
    ///
    /// # Errors
    /// Returns an error if file upload fails
    ///
    /// # Panics
    /// Panics if file has no filename
    pub fn upload_file(&self, local_path: &std::path::Path, remote_path: &str) -> Result<()> {
        const CHUNK_SIZE: usize = 8192;

        let file_size = std::fs::metadata(local_path)
            .map_err(|e| miette!("Failed to get file metadata: {}", e))?
            .len();

        let pb = ui::progress_bar(
            file_size,
            &format!(
                "Uploading {}",
                local_path.file_name().unwrap().to_string_lossy()
            ),
        );

        let mut file = std::fs::File::open(local_path)
            .map_err(|e| miette!("Failed to open file {}: {}", local_path.display(), e))?;

        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)
            .map_err(|e| miette!("Failed to read file: {e}"))?;

        let mut channel = self
            .session
            .scp_send(
                std::path::Path::new(remote_path),
                0o755, // executable permissions
                file_data.len() as u64,
                None,
            )
            .map_err(|e| miette!("Failed to create SCP channel: {e}"))?;

        for chunk in file_data.chunks(CHUNK_SIZE) {
            channel
                .write_all(chunk)
                .map_err(|e| miette!("Failed to write file data: {e}"))?;
            pb.inc(chunk.len() as u64);
        }

        channel
            .send_eof()
            .map_err(|e| miette!("Failed to send EOF: {e}"))?;

        channel
            .wait_eof()
            .map_err(|e| miette!("Failed to wait for EOF: {e}"))?;

        channel
            .close()
            .map_err(|e| miette!("Failed to close SCP channel: {e}"))?;

        channel
            .wait_close()
            .map_err(|e| miette!("Failed to wait for channel close: {e}"))?;

        pb.finish_with_message(format!(
            "✓ Uploaded {}",
            local_path.file_name().unwrap().to_string_lossy()
        ));

        Ok(())
    }

    pub(crate) fn is_container(&self) -> bool {
        self.is_container
    }

    fn test_sudo(&self) -> Result<Option<String>> {
        // test if we already have passwordless sudo
        if self.execute_command_raw("sudo -n true", None).is_ok() {
            return Ok(None);
        }

        let password = ui::password(&format!("[sudo] password for {}", self.user))?;

        match self.execute_command_with_sudo("true", &password, None) {
            Ok(_) => Ok(Some(password)),
            Err(_) => Err(miette!("Invalid sudo password")),
        }
    }

    fn execute_command_raw(&self, command: &str, timeout: Option<Duration>) -> Result<String> {
        self.execute_command_raw_with_stdin(command, None, timeout)
    }

    fn execute_command_raw_with_stdin(
        &self,
        command: &str,
        stdin: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<String> {
        let session = &self.session;

        if let Some(timeout) = timeout {
            session.set_timeout(
                u32::try_from(timeout.as_millis()).map_err(|e| miette!("Invalid timeout: {e}"))?,
            );
        }

        let mut channel = session
            .channel_session()
            .map_err(|e| miette!("Failed to open channel: {e}"))?;

        channel
            .exec(command)
            .map_err(|e| miette!("Failed to execute command '{command}': {e}"))?;

        if let Some(data) = stdin {
            channel
                .write_all(data.as_bytes())
                .map_err(|e| miette!("Failed to write to command stdin: {e}"))?;
            channel
                .send_eof()
                .map_err(|e| miette!("Failed to send EOF: {e}"))?;
        }

        let mut output = String::new();
        channel
            .read_to_string(&mut output)
            .map_err(|e| miette!("Failed to read command output: {e}"))?;

        let mut stderr = String::new();
        channel
            .stderr()
            .read_to_string(&mut stderr)
            .map_err(|e| miette!("Failed to read stderr: {e}"))?;

        channel
            .wait_close()
            .map_err(|e| miette!("Failed to close channel: {e}"))?;

        let exit_status = channel
            .exit_status()
            .map_err(|e| miette!("Failed to get exit status: {e}"))?;

        if timeout.is_some() {
            session.set_timeout(0);
        }

        if exit_status == 0 {
            Ok(output)
        } else {
            let error_msg = if !stderr.is_empty() {
                stderr.trim()
            } else if !output.is_empty() {
                output.trim()
            } else {
                "Command failed with no output"
            };
            Err(miette!(
                "Command '{command}' failed with exit code {exit_status}: {error_msg}"
            ))
        }
    }

    fn execute_command_with_sudo(
        &self,
        command: &str,
        password: &str,
        timeout: Option<Duration>,
    ) -> Result<String> {
        // provide our own `sudo -S` and feed the password over the encrypted
        // channel stdin (never via the remote process arguments)
        let sudo_command = wrap_sudo_command(command);
        self.execute_command_raw_with_stdin(&sudo_command, Some(&format!("{password}\n")), timeout)
    }
}

pub(crate) fn parse_ssh_target(target: &str) -> Result<(String, String, Option<u16>)> {
    let (user, host_port) = target
        .split_once('@')
        .ok_or_else(|| miette!("Invalid SSH target format. Expected user@host[:port]"))?;

    if user.is_empty() {
        return Err(miette!("User cannot be empty"));
    }

    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        // bracketed IPv6 literal: [::1] or [::1]:2222
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| miette!("Invalid IPv6 SSH target: missing ']'"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().map_err(|_| miette!("Invalid port: {p}"))?),
            None if after.is_empty() => None,
            None => {
                return Err(miette!(
                    "Unexpected characters after IPv6 address: {after:?}"
                ));
            }
        };
        (addr.to_string(), port)
    } else if let Some((h, p)) = host_port.rsplit_once(':')
        && !h.contains(':')
    {
        // exactly one colon: host:port (a bare IPv6 has multiple colons and is
        // handled by the else branch)
        (
            h.to_string(),
            Some(p.parse::<u16>().map_err(|_| miette!("Invalid port: {p}"))?),
        )
    } else {
        // hostname / IPv4 with no port, or a bare IPv6 literal
        (host_port.to_string(), None)
    };

    if host.is_empty() {
        return Err(miette!("Host cannot be empty"));
    }

    Ok((user.to_string(), host, port))
}

/// Verify the server's host key against `~/.ssh/known_hosts`, trusting it on
/// first use (TOFU). A mismatch is treated as a potential machine-in-the-middle
/// and aborts the connection before any credentials are sent.
fn verify_host_key(session: &Session, host: &str, port: u16) -> Result<()> {
    let Some(home) = dirs::home_dir() else {
        return Err(miette!(
            "Cannot determine home directory for host key verification"
        ));
    };
    let kh_path = home.join(".ssh").join("known_hosts");

    let mut known_hosts = session
        .known_hosts()
        .map_err(|e| miette!("Failed to initialise known_hosts: {e}"))?;

    if kh_path.exists() {
        known_hosts
            .read_file(&kh_path, KnownHostFileKind::OpenSSH)
            .map_err(|e| miette!("Failed to read {}: {e}", kh_path.display()))?;
    }

    let (key, key_type) = session
        .host_key()
        .ok_or_else(|| miette!("Server did not present a host key"))?;

    match known_hosts.check_port(host, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => Err(miette!(
            "SSH host key mismatch for {host}:{port} — possible machine-in-the-middle. \
             If the host key legitimately changed, remove the stale entry from {}.",
            kh_path.display()
        )),
        CheckResult::Failure => Err(miette!("Host key verification failed for {host}:{port}")),
        CheckResult::NotFound => {
            append_known_host(&kh_path, host, port, key, key_type)?;
            ui::info(&format!(
                "Trusting new host key for {host}:{port} (added to {})",
                kh_path.display()
            ));
            Ok(())
        }
    }
}

/// Build the command to run under `sudo -S` (password supplied on stdin).
///
/// Strips a single leading `sudo ` so we never produce `sudo sudo …`, and uses
/// `-p ''` to suppress the prompt. Note that the leading `sudo ` of a *compound*
/// command (`sudo a && sudo b`) is all that is rewritten — the password is fed
/// once, to the first `sudo -S`.
fn wrap_sudo_command(command: &str) -> String {
    let inner = command.strip_prefix("sudo ").unwrap_or(command);
    format!("sudo -S -p '' {inner}")
}

/// Format an OpenSSH `known_hosts` line (without trailing newline) for a host key.
///
/// Returns `None` for an unknown key type that cannot be recorded. Non-default
/// ports use the OpenSSH `[host]:port` form.
fn known_host_line(host: &str, port: u16, key: &[u8], key_type: HostKeyType) -> Option<String> {
    let key_type_str = match key_type {
        HostKeyType::Rsa => "ssh-rsa",
        HostKeyType::Dss => "ssh-dss",
        HostKeyType::Ecdsa256 => "ecdsa-sha2-nistp256",
        HostKeyType::Ecdsa384 => "ecdsa-sha2-nistp384",
        HostKeyType::Ecdsa521 => "ecdsa-sha2-nistp521",
        HostKeyType::Ed25519 => "ssh-ed25519",
        HostKeyType::Unknown => return None,
    };

    let host_field = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };

    Some(format!(
        "{host_field} {key_type_str} {}",
        STANDARD.encode(key)
    ))
}

/// Append a host key to `known_hosts` in OpenSSH format (used for trust-on-first-use).
fn append_known_host(
    path: &Path,
    host: &str,
    port: u16,
    key: &[u8],
    key_type: HostKeyType,
) -> Result<()> {
    let line = known_host_line(host, port, key, key_type)
        .ok_or_else(|| miette!("Unknown host key type; refusing to record it"))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette!("Failed to create {}: {e}", parent.display()))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| miette!("Failed to open {}: {e}", path.display()))?;

    file.write_all(format!("{line}\n").as_bytes())
        .map_err(|e| miette!("Failed to write to {}: {e}", path.display()))?;

    Ok(())
}

/// RAII guard that puts the terminal into raw mode and restores it on drop.
struct RawModeGuard {
    original: libc::termios,
}

impl RawModeGuard {
    fn enter() -> std::io::Result<Self> {
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &raw mut original) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            let mut raw = original;
            libc::cfmakeraw(&raw mut raw);
            // Keep ISIG so Ctrl-C still works locally
            raw.c_lflag |= libc::ISIG;

            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const raw) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(Self { original })
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const self.original);
        }
    }
}

fn find_ssh_keys() -> Vec<PathBuf> {
    let mut keys = Vec::new();

    if let Some(home_dir) = dirs::home_dir() {
        let key_names = ["id_ed25519", "id_rsa", "id_dsa", "id_ecdsa"];

        for key_name in &key_names {
            let key_path = home_dir.join(".ssh").join(key_name);
            if key_path.exists() {
                keys.push(key_path);
            }
        }
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_target_without_port() {
        let result = parse_ssh_target("root@192.168.1.1").unwrap();
        assert_eq!(
            result,
            ("root".to_string(), "192.168.1.1".to_string(), None)
        );
    }

    #[test]
    fn test_parse_ssh_target_with_port() {
        let result = parse_ssh_target("root@192.168.1.1:2222").unwrap();
        assert_eq!(
            result,
            ("root".to_string(), "192.168.1.1".to_string(), Some(2222))
        );
    }

    #[test]
    fn test_parse_ssh_target_ipv6() {
        let result = parse_ssh_target("root@[2001:db8::1]:2222").unwrap();
        assert_eq!(
            result,
            ("root".to_string(), "2001:db8::1".to_string(), Some(2222))
        );

        let result = parse_ssh_target("root@[::1]").unwrap();
        assert_eq!(result, ("root".to_string(), "::1".to_string(), None));

        // bare IPv6 with no brackets and no port
        let result = parse_ssh_target("root@2001:db8::1").unwrap();
        assert_eq!(
            result,
            ("root".to_string(), "2001:db8::1".to_string(), None)
        );
    }

    #[test]
    fn test_parse_ssh_target_invalid_format() {
        assert!(parse_ssh_target("invalid").is_err());
        assert!(parse_ssh_target("@host").is_err());
        assert!(parse_ssh_target("user@").is_err());
        assert!(parse_ssh_target("user@host:notaport").is_err());
    }

    #[test]
    fn test_wrap_sudo_command_strips_leading_sudo() {
        // no double sudo: a leading `sudo ` is stripped before our `sudo -S`
        assert_eq!(
            wrap_sudo_command("sudo systemctl restart makiatto"),
            "sudo -S -p '' systemctl restart makiatto"
        );
    }

    #[test]
    fn test_wrap_sudo_command_wraps_bare_command() {
        // used by the sudo probe (`true`) and any non-sudo-prefixed command
        assert_eq!(wrap_sudo_command("true"), "sudo -S -p '' true");
    }

    #[test]
    fn test_wrap_sudo_command_only_first_sudo_in_compound() {
        // documents the known limitation: only the leading sudo is rewritten;
        // the second relies on sudo's credential cache
        assert_eq!(
            wrap_sudo_command("sudo apt update && sudo apt install -y x"),
            "sudo -S -p '' apt update && sudo apt install -y x"
        );
    }

    #[test]
    fn test_known_host_line_default_port() {
        let line = known_host_line("example.com", 22, b"\x00\x01\x02", HostKeyType::Rsa).unwrap();
        assert_eq!(line, "example.com ssh-rsa AAEC");
    }

    #[test]
    fn test_known_host_line_custom_port_is_bracketed() {
        let line =
            known_host_line("10.0.0.1", 2222, b"\x00\x01\x02", HostKeyType::Ed25519).unwrap();
        assert_eq!(line, "[10.0.0.1]:2222 ssh-ed25519 AAEC");
    }

    #[test]
    fn test_known_host_line_unknown_type_is_rejected() {
        assert!(known_host_line("h", 22, b"abc", HostKeyType::Unknown).is_none());
    }
}
