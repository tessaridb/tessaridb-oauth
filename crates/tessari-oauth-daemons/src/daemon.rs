//! What a daemon is: a named piece of periodic work with its cadence and a bound on one run.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::Result;

/// What one run reports for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonReport {
    /// A short structured summary, free of secret material.
    pub message: String,
}

/// One run's future.
pub type DaemonFuture<'a> = Pin<Box<dyn Future<Output = Result<DaemonReport>> + Send + 'a>>;

/// Periodic background work. A daemon holds what it needs from construction, so a run takes no arguments and the
/// daemon is testable without a process around it.
pub trait Daemon: Send + Sync {
    /// The daemon's name, carried by every log line about it.
    fn name(&self) -> &'static str;

    /// How often it runs.
    fn interval(&self) -> Duration;

    /// The most one run may take before it is cut.
    fn timeout(&self) -> Duration;

    /// One run.
    fn run_once(&self) -> DaemonFuture<'_>;
}
