use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use miette::Result;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

/// Generic service manager for handling service lifecycle
#[derive(Clone)]
pub struct ServiceManager<T: Send + 'static> {
    pub tx: mpsc::UnboundedSender<T>,
}

impl<T: Send + 'static> ServiceManager<T> {
    /// Send a command to the service
    ///
    /// # Errors
    /// Returns an error if the service manager task has stopped
    pub fn send(&self, command: T) -> Result<()> {
        self.tx
            .send(command)
            .map_err(|_| miette::miette!("Failed to send command - service may have stopped"))
    }
}

/// Common commands that most services will need
#[derive(Debug)]
pub enum BasicServiceCommand {
    Restart {
        response: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<()>>,
    },
}

impl BasicServiceCommand {
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        matches!(self, Self::Shutdown { .. })
    }
}

#[allow(async_fn_in_trait)]
pub trait BasicServiceManager {
    async fn restart(&self) -> Result<()>;
    async fn shutdown(&self) -> Result<()>;
}

impl BasicServiceManager for ServiceManager<BasicServiceCommand> {
    async fn restart(&self) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(BasicServiceCommand::Restart {
            response: response_tx,
        })?;
        response_rx
            .await
            .map_err(|_| miette::miette!("Failed to receive restart response"))?
    }

    async fn shutdown(&self) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(BasicServiceCommand::Shutdown {
            response: response_tx,
        })?;
        response_rx
            .await
            .map_err(|_| miette::miette!("Failed to receive shutdown response"))?
    }
}

/// Set up a generic service with management capabilities
///
/// # Errors
/// Returns an error if the service fails to initialise
pub fn setup<F, S>(
    service_name: &'static str,
    config: Arc<crate::config::Config>,
    tripwire: tripwire::Tripwire,
    start_fn: F,
) -> Result<(
    ServiceManager<BasicServiceCommand>,
    tokio::task::JoinHandle<Result<()>>,
)>
where
    F: Fn(Arc<crate::config::Config>, tripwire::Tripwire) -> S + Send + 'static,
    S: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel();
    let manager = ServiceManager { tx };

    let handle = tokio::spawn(async move {
        let mut current_server = Some(tokio::spawn(start_fn(config.clone(), tripwire.clone())));

        loop {
            tokio::select! {
                command = rx.recv() => {
                    let Some(command) = command else {
                        break;
                    };

                    match command {
                        BasicServiceCommand::Restart { response } => {
                            info!("Restarting {service_name} service");

                            if let Some(server) = current_server.take() {
                                server.abort();
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }

                            let new_server = tokio::spawn(start_fn(config.clone(), tripwire.clone()));
                            current_server = Some(new_server);
                            let _ = response.send(Ok(()));
                        }
                        BasicServiceCommand::Shutdown { response } => {
                            info!("Shutting down {service_name} service");

                            if let Some(server) = current_server.take() {
                                server.abort();
                            }

                            let _ = response.send(Ok(()));
                            break;
                        }
                    }
                }
                () = tripwire.clone() => {
                    info!("{service_name} manager received shutdown signal");
                    if let Some(server) = current_server.take() {
                        server.abort();
                    }
                    break;
                }
            }
        }

        if let Some(server) = current_server {
            server.abort();
        }

        Ok(())
    });

    Ok((manager, handle))
}

/// Handle service restart signals with debouncing
///
/// This function listens for restart signals and forwards them to the service manager
/// with debouncing to prevent rapid restarts. Only one restart can be pending at a time.
///
/// # Errors
/// Returns an error if the service manager channel is closed
pub async fn handle_restarts(
    service_name: &'static str,
    mut restart_rx: mpsc::Receiver<()>,
    manager: ServiceManager<BasicServiceCommand>,
) -> std::result::Result<&'static str, String> {
    let restart_pending = Arc::new(AtomicBool::new(false));

    while let Some(()) = restart_rx.recv().await {
        if !restart_pending.swap(true, Ordering::SeqCst) {
            let restart_pending_clone = restart_pending.clone();
            let (response_tx, response_rx) = oneshot::channel();

            if let Err(e) = manager.send(BasicServiceCommand::Restart {
                response: response_tx,
            }) {
                tracing::error!("Failed to send {service_name} restart command: {e}");
                restart_pending.store(false, Ordering::SeqCst);
                continue;
            }

            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                match response_rx.await {
                    Ok(Ok(())) => info!("{service_name} server restarted"),
                    Ok(Err(e)) => tracing::error!("Failed to restart {service_name} server: {e}"),
                    Err(e) => tracing::error!("{service_name} restart response error: {e}"),
                }

                restart_pending_clone.store(false, Ordering::SeqCst);
            });
        }
    }
    Ok("restart_handler")
}
