//! The peer directories daemon: reads, from every other region, where its issuers are and which companies it
//! serves, and makes that the node's knowledge of companies served elsewhere, so a request for one of them can be
//! sent to its home.
//!
//! A peer that cannot be read keeps the entries it last gave: one unreachable region must not make its companies
//! unknown here, which would answer their users with "not found" instead of sending them home. A peer that answers
//! but has recorded no base URL has nowhere to send anybody, so it contributes nothing.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::future::join_all;
use tessari_oauth_storage::companies::{CompanyService, Elsewhere};
use tessari_oauth_types::TenantId;

use crate::Result;
use crate::daemon::{Daemon, DaemonFuture, DaemonReport};

const NAME: &str = "peer-directories";

/// What one region's directory says: the base URL of its issuers, when recorded, and its active companies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHomes {
    /// The region's public base URL, `None` when the region has not recorded one.
    pub base: Option<Arc<str>>,
    /// The companies the region serves.
    pub companies: Vec<TenantId>,
}

/// One other region's directory, as this node may read it.
pub trait PeerDirectory: Send + Sync {
    /// Read the region's base URL and active companies.
    fn read(
        &self,
    ) -> Pin<Box<dyn Future<Output = tessari_oauth_storage::Result<PeerHomes>> + Send + '_>>;
}

/// A region's directory read through a connection that may read that directory and nothing else.
impl PeerDirectory for CompanyService {
    fn read(
        &self,
    ) -> Pin<Box<dyn Future<Output = tessari_oauth_storage::Result<PeerHomes>> + Send + '_>> {
        Box::pin(async move {
            let base = self.base().await?.map(Arc::from);
            let companies = self.active().await?;
            Ok(PeerHomes { base, companies })
        })
    }
}

/// One peer region: its name, for the log, and its directory.
pub struct Peer {
    /// The region's name.
    pub region: String,
    /// Its directory.
    pub directory: Arc<dyn PeerDirectory>,
}

/// The peer directories daemon and everything a run needs.
pub struct PeerDirectories {
    peers: Vec<Peer>,
    elsewhere: Arc<Elsewhere>,
    last: Mutex<Vec<Option<PeerHomes>>>,
    interval: Duration,
    timeout: Duration,
}

impl PeerDirectories {
    /// The daemon reading `peers` into `elsewhere` every `interval`, each run bounded by `timeout`.
    #[must_use]
    pub fn new(
        peers: Vec<Peer>,
        elsewhere: Arc<Elsewhere>,
        interval: Duration,
        timeout: Duration,
    ) -> Self {
        let last = Mutex::new(vec![None; peers.len()]);
        Self {
            peers,
            elsewhere,
            last,
            interval,
            timeout,
        }
    }

    async fn run(&self) -> Result<DaemonReport> {
        let reads = join_all(self.peers.iter().map(|peer| peer.directory.read())).await;
        let mut answered = 0_usize;
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        for ((peer, read), kept) in self.peers.iter().zip(reads).zip(last.iter_mut()) {
            match read {
                Ok(homes) => {
                    answered = answered.saturating_add(1);
                    *kept = Some(homes);
                }
                Err(failure) => tracing::warn!(
                    daemon = NAME,
                    region = %peer.region,
                    category = ?failure.category(),
                    "a peer region's directory was not read; its last entries are kept"
                ),
            }
        }
        // The first peer naming a company is its home, so the answer does not depend on which read finished first.
        let mut homes: HashMap<TenantId, Arc<str>> = HashMap::new();
        for kept in last.iter().flatten() {
            let Some(base) = &kept.base else { continue };
            for company in &kept.companies {
                homes
                    .entry(company.clone())
                    .or_insert_with(|| Arc::clone(base));
            }
        }
        drop(last);
        let companies = homes.len();
        self.elsewhere.replace(homes);
        Ok(DaemonReport {
            message: format!(
                "peers={} answered={answered} companies={companies}",
                self.peers.len()
            ),
        })
    }
}

impl Daemon for PeerDirectories {
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

#[cfg(test)]
#[path = "peer_directories_tests.rs"]
mod tests;
