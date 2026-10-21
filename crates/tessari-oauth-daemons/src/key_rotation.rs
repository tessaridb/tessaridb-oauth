//! The key rotation daemon: applies the rotation rule to every configured tenant on each run.
//!
//! For a tenant it reads the live keys, asks `keys::plan` at the daemon's clock, makes a successor when the rule asks
//! — generated, sealed and recorded with its public half, the plaintext never leaving custody — and then retires what
//! the rule retires. Making before retiring means a run cut in between leaves one key too many, never none. Tenants
//! are independent, so a run works on several at once, and one tenant's failure is reported without stopping the
//! others; the next run retries it, because the rule decides from the stored state alone.

use std::sync::Arc;
use std::time::Duration;

use tessari_oauth_constants::KEY_ROTATION_CONCURRENCY;
use tessari_oauth_core::keys::{self, KeyRecord};
use tessari_oauth_infrastructure::custody::{Kek, SigningKey};
use tessari_oauth_storage::keys::{KeyService, StoredKey};
use tessari_oauth_types::{Algorithm, Clock, ErrorCategory, TenantId, Timestamp};
use tokio::task::JoinSet;

use crate::daemon::{Daemon, DaemonFuture, DaemonReport};
use crate::{Error, Result};

/// The rotation daemon and everything a run needs.
pub struct KeyRotation {
    /// The tenants' key records.
    pub keys: Arc<KeyService>,
    /// The key-encryption key new keys are sealed under.
    pub kek: Arc<Kek>,
    /// The tenants this server signs for.
    pub tenants: Vec<TenantId>,
    /// The algorithm new keys sign with.
    pub algorithm: Algorithm,
    /// The run's clock.
    pub clock: Clock,
    /// How often it runs.
    pub interval: Duration,
    /// The most one run may take.
    pub timeout: Duration,
}

const NAME: &str = "key-rotation";

/// What a run did to one tenant.
#[derive(Default)]
struct Outcome {
    generated: usize,
    retired: usize,
}

/// The parts of the daemon one tenant's work needs, cloned into its task.
#[derive(Clone)]
struct Custody {
    keys: Arc<KeyService>,
    kek: Arc<Kek>,
    algorithm: Algorithm,
}

/// A successor for `tenant`, sealed and recorded as made at `now`.
async fn make_key(
    custody: &Custody,
    tenant: &TenantId,
    now: Timestamp,
) -> std::result::Result<(), String> {
    let (key, pkcs8) =
        SigningKey::generate(custody.algorithm).map_err(|error| error.to_string())?;
    let sealed = custody
        .kek
        .seal(tenant, key.kid().as_str(), &pkcs8)
        .map_err(|error| error.to_string())?;
    let stored = StoredKey {
        kid: key.kid().clone(),
        algorithm: key.algorithm(),
        sealed,
        public_jwk: key.public_jwk().map_err(|error| error.to_string())?,
        created_at: now,
        compromised: false,
    };
    custody
        .keys
        .add(tenant, &stored)
        .await
        .map_err(|error| error.to_string())
}

/// Apply the rule to `tenant` at `now`.
async fn rotate(
    custody: Custody,
    tenant: TenantId,
    now: Timestamp,
) -> std::result::Result<Outcome, String> {
    let live = custody
        .keys
        .live(&tenant)
        .await
        .map_err(|error| error.to_string())?;
    let records: Vec<KeyRecord> = live
        .into_iter()
        .map(|key| KeyRecord {
            kid: key.kid,
            created_at: key.created_at,
            compromised: key.compromised,
        })
        .collect();
    let plan = keys::plan(&records, now);
    let mut outcome = Outcome::default();
    if plan.generate {
        make_key(&custody, &tenant, now).await?;
        outcome.generated = 1;
    }
    for kid in &plan.retire {
        custody
            .keys
            .retire(&tenant, kid, now)
            .await
            .map_err(|error| error.to_string())?;
        outcome.retired = outcome.retired.saturating_add(1);
    }
    Ok(outcome)
}

impl KeyRotation {
    async fn run(&self) -> Result<DaemonReport> {
        let now = (self.clock)();
        let custody = Custody {
            keys: Arc::clone(&self.keys),
            kek: Arc::clone(&self.kek),
            algorithm: self.algorithm,
        };
        let mut pending = self.tenants.iter().cloned();
        let mut tasks = JoinSet::new();
        let (mut generated, mut retired) = (0_usize, 0_usize);
        let mut failures: Vec<String> = Vec::new();
        loop {
            while tasks.len() < KEY_ROTATION_CONCURRENCY {
                let Some(tenant) = pending.next() else { break };
                let custody = custody.clone();
                tasks.spawn(async move {
                    let outcome = rotate(custody, tenant.clone(), now).await;
                    (tenant, outcome)
                });
            }
            let Some(joined) = tasks.join_next().await else {
                break;
            };
            match joined {
                Ok((_, Ok(outcome))) => {
                    generated = generated.saturating_add(outcome.generated);
                    retired = retired.saturating_add(outcome.retired);
                }
                Ok((tenant, Err(message))) => {
                    failures.push(format!("{}: {message}", tenant.as_str()))
                }
                Err(join) => failures.push(format!("a tenant's task ended abnormally: {join}")),
            }
        }
        let tenants = self.tenants.len();
        if failures.is_empty() {
            Ok(DaemonReport {
                message: format!("tenants={tenants} generated={generated} retired={retired}"),
            })
        } else {
            Err(Error::Run {
                daemon: NAME,
                message: format!(
                    "{} of {tenants} tenants failed (generated={generated} retired={retired}): {}",
                    failures.len(),
                    failures.join("; ")
                ),
                category: ErrorCategory::Unavailable,
            })
        }
    }
}

impl Daemon for KeyRotation {
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
