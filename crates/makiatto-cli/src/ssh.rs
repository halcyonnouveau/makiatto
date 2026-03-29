use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use miette::{Result, miette};
use ssh2::Session;

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
        let port = port.unwrap_or(22);
        let (user, host) = parse_ssh_target(ssh_target)?;

        let tcp = TcpStream::connect((host.as_str(), port))
            .map_err(|e| miette!("Failed to connect to {host}:{port}: {e}"))?;

        let mut session =
            Session::new().map_err(|e| miette!("Failed to create SSH session: {e}"))?;

        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|e| miette!("SSH handshake failed: {e}"))?;

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

        if cfg!(debug_assertions) {
            ssh.is_container = ssh
                .execute_command_raw("[ -f /run/.containerenv ] || [ -f /.dockerenv ]", None)
                .is_ok();
        }

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
        let command = if let Some(password) = &self.password
            && command.starts_with("sudo ")
        {
            format!("echo '{password}' | sudo -S {command}")
        } else {
            command.to_string()
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

        // Set channel to non-blocking so we can interleave reads and writes
        self.session.set_blocking(false);

        // Put local terminal into raw mode so keypresses are forwarded immediately
        let _raw_guard = RawModeGuard::enter()
            .map_err(|e| miette!("Failed to enable raw terminal mode: {e}"))?;

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
        let sudo_command = format!("echo '{password}' | sudo -S {command}");
        self.execute_command_raw(&sudo_command, timeout)
    }
}

pub(crate) fn parse_ssh_target(target: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = target.split('@').collect();
    if parts.len() != 2 {
        return Err(miette!(
            "Invalid SSH target format. Expected user@host:port"
        ));
    }

    let user = parts[0].to_string();

    if user.is_empty() {
        return Err(miette!("User cannot be empty"));
    }

    let host_port = parts[1];

    let host_parts: Vec<&str> = host_port.split(':').collect();
    let host = host_parts[0].to_string();

    if host.is_empty() {
        return Err(miette!("Host cannot be empty"));
    }

    Ok((user, host))
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
        assert_eq!(result, ("root".to_string(), "192.168.1.1".to_string()));
    }

    #[test]
    fn test_parse_ssh_target_invalid_format() {
        assert!(parse_ssh_target("invalid").is_err());
        assert!(parse_ssh_target("@host").is_err());
        assert!(parse_ssh_target("user@").is_err());
    }
}
