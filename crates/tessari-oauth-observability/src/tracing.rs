//! The process's subscriber: one JSON object per event on standard output, written by a background thread so a log
//! line never blocks the runtime, filtered by `RUST_LOG` (`info` when unset or unreadable).

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use crate::{Error, Result};

/// Install the subscriber for this process. The returned guard flushes the writer when dropped, so the caller keeps
/// it for the life of the process.
///
/// # Errors
///
/// [`Error::AlreadyInstalled`] when this process already has a subscriber.
pub fn init_tracing() -> Result<WorkerGuard> {
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(writer)
        .with_env_filter(filter)
        .try_init()
        .map_err(|_| Error::AlreadyInstalled)?;
    Ok(guard)
}

#[cfg(test)]
#[path = "tracing_tests.rs"]
mod tests;
