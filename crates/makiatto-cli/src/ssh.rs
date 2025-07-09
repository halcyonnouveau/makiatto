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
    user: String,
    password: Option<String>,
}

impl SshSession {
    pub fn new(ssh_target: &str, key_path: &Option<PathBuf>) -> Result<Self> {
        let (user, host, port) = parse_ssh_target(ssh_target)?;
        let mut password = None;

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
        } else {
            if session.userauth_agent(&user).is_ok() {
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
                    let user_password = ui::password(&format!("[ssh] password for {user}"))?;

                    session
                        .userauth_password(&user, &user_password)
                        .map_err(|e| miette!("SSH password authentication failed: {}", e))?;

                    password = Some(user_password);
                }
            }
        }

        let mut ssh = Self {
            session,
            user,
            password: password.clone(),
        };

        if password.is_none() {
            ssh.password = ssh.test_sudo()?;
        }

        Ok(ssh)
    }

    pub fn exec(&self, command: &str) -> Result<String> {
        if command.starts_with("sudo ") && self.password.is_some() {
            let password = self.password.as_ref().unwrap();
            return self.execute_command_with_sudo(command, password, None);
        }

        self.execute_command_raw(command, None)
    }

    #[allow(dead_code)]
    pub fn exec_timeout(&self, command: &str, timeout: Duration) -> Result<String> {
        if command.starts_with("sudo ") && self.password.is_some() {
            let password = self.password.as_ref().unwrap();
            return self.execute_command_with_sudo(command, password, Some(timeout));
        }

        self.execute_command_raw(command, Some(timeout))
    }

    pub fn upload_file(&self, local_path: &std::path::Path, remote_path: &str) -> Result<()> {
        use std::io::Read;

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

        const CHUNK_SIZE: usize = 8192;
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

    pub(crate) fn is_remote_container(&self) -> Result<bool> {
        match self.execute_command_raw("test -f /run/.containerenv", None) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
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
            session.set_timeout(timeout.as_millis() as u32);
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

pub(crate) fn parse_ssh_target(target: &str) -> Result<(String, String, u16)> {
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

    let port = if host_parts.len() > 1 {
        host_parts[1]
            .parse::<u16>()
            .map_err(|_| miette!("Invalid port number"))?
    } else {
        22
    };

    Ok((user, host, port))
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
    fn test_parse_ssh_target_with_port() {
        let result = parse_ssh_target("user@example.com:2222").unwrap();
        assert_eq!(
            result,
            ("user".to_string(), "example.com".to_string(), 2222)
        );
    }

    #[test]
    fn test_parse_ssh_target_without_port() {
        let result = parse_ssh_target("root@192.168.1.1").unwrap();
        assert_eq!(result, ("root".to_string(), "192.168.1.1".to_string(), 22));
    }

    #[test]
    fn test_parse_ssh_target_invalid_format() {
        assert!(parse_ssh_target("invalid").is_err());
        assert!(parse_ssh_target("@host").is_err());
        assert!(parse_ssh_target("user@").is_err());
    }

    #[test]
    fn test_parse_ssh_target_invalid_port() {
        assert!(parse_ssh_target("user@host:abc").is_err());
        assert!(parse_ssh_target("user@host:99999").is_err());
    }

    #[test]
    fn test_parse_ssh_target_ipv4() {
        let result = parse_ssh_target("admin@10.0.0.1:8022").unwrap();
        assert_eq!(result, ("admin".to_string(), "10.0.0.1".to_string(), 8022));
    }
}
