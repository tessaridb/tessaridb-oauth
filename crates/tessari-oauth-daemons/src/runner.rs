//! The runner: one daemon on its interval until shutdown, each run bounded by the daemon's timeout.
//!
//! Shutdown is checked first on every turn, so a pending signal always wins over a due tick; a run already started
//! finishes (within its timeout) rather than being dropped halfway, and no run starts after the signal.

use std::sync::Arc;

use tokio::sync::watch;

use crate::daemon::Daemon;

/// Run `daemon` until `shutdown` changes or its sender is gone.
pub async fn run(daemon: Arc<dyn Daemon>, mut shutdown: watch::Receiver<bool>) {
    let name = daemon.name();
    let mut ticker = tokio::time::interval(daemon.interval());
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                tracing::info!(daemon = name, "shutdown signal");
                break;
            }
            _ = ticker.tick() => {
                let timeout = daemon.timeout();
                match tokio::time::timeout(timeout, daemon.run_once()).await {
                    Ok(Ok(report)) => {
                        tracing::info!(daemon = name, result = %report.message, "completed");
                    }
                    Ok(Err(error)) => tracing::error!(daemon = name, %error, "failed"),
                    Err(_) => {
                        tracing::error!(daemon = name, timeout_secs = timeout.as_secs(), "timed out");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;
