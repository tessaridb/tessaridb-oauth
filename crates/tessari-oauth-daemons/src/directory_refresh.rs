//! The directory refresh daemon: re-reads which companies are active and makes the node serve exactly those, so a
//! company created, suspended or resumed on any node is served or refused here within one interval.
//!
//! A run that cannot read the directory leaves the snapshot as it was: a store outage must not stop every company
//! from being served.

use std::sync::Arc;
use std::time::Duration;

use tessari_oauth_storage::companies::{CompanyService, Served};

use crate::daemon::{Daemon, DaemonFuture, DaemonReport};
use crate::{Error, Result};

const NAME: &str = "directory-refresh";

/// The refresh daemon and everything a run needs.
pub struct DirectoryRefresh {
    /// The region's directory.
    pub companies: Arc<CompanyService>,
    /// The snapshot the node serves from.
    pub served: Arc<Served>,
    /// How often it runs.
    pub interval: Duration,
    /// The most one run may take.
    pub timeout: Duration,
}

impl DirectoryRefresh {
    async fn run(&self) -> Result<DaemonReport> {
        let active = self
            .companies
            .active()
            .await
            .map_err(|failure| Error::Run {
                daemon: NAME,
                message: failure.to_string(),
                category: failure.category(),
            })?;
        let count = active.len();
        self.served.replace(active);
        Ok(DaemonReport {
            message: format!("companies={count}"),
        })
    }
}

impl Daemon for DirectoryRefresh {
    fn name(&self) -> &'static str {
        NAME
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn run_once(&self) -> DaemonFuture<'_> {
        Box::pin(self.run())
    }
}
