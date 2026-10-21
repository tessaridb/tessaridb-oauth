//! The code service: issue a code's bindings, and consume them exactly once.
//!
//! Single use is a concurrency property. A read followed by a write lets two simultaneous redemptions both pass the
//! read, so the spend is ONE conditional write — set `redeemed_at` only while it is absent — and the store refuses
//! the loser. What the loser is told is decided by reading the record again rather than by the refusal's wording,
//! because two different refusals mean "somebody else spent it" and a third means nothing of the sort; the state
//! answers that, the sentence does not.
//!
//! A loser can also be told `retry`: its commit met the winner's while that one was still landing in its group sync,
//! and a read at that moment can still show the code unspent. So a `retry` is answered by trying the spend again,
//! a bounded number of times, never by reading.

use std::sync::Arc;
use std::time::Duration;

use tessari_oauth_constants::{CODE_SPEND_ATTEMPTS, CODE_SPEND_FIRST_PAUSE_MS};
use tessari_oauth_core::codes::IssuedCode;
use tessari_oauth_types::{AuthorizationCode, Challenge, ClientId, ScopeSet, TenantId, Timestamp};

use tessari_oauth_infrastructure::tessaridb::Place;

use super::CodeEntity;
use super::repository::CodeRepository;
use crate::{Error, Result, Tenancy};

/// What a consume found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consumed {
    /// This call spent the code; its bindings are for the token endpoint to check.
    Fresh(IssuedCode),
    /// The code had already been spent — a replay, which means the code leaked.
    Replayed(IssuedCode),
    /// No such code.
    Absent,
}

/// Issued authorization codes.
#[derive(Clone)]
pub struct CodeService {
    repository: Arc<dyn CodeRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "code",
        reason: reason.to_owned(),
    }
}

fn to_entity(code: &IssuedCode) -> Result<CodeEntity> {
    Ok(CodeEntity {
        tenant: code.tenant.as_str().to_owned(),
        client_id: code.client_id.as_str().to_owned(),
        redirect_uri: code.redirect_uri.clone(),
        challenge: code.challenge.as_str().to_owned(),
        scopes: code.scopes.iter().map(str::to_owned).collect(),
        expires_at: i64::try_from(code.expires_at.unix_secs())
            .map_err(|_| unreadable("expiry beyond i64"))?,
        redeemed_at: None,
    })
}

fn to_model(row: CodeEntity) -> Result<IssuedCode> {
    let seconds = u64::try_from(row.expires_at).map_err(|_| unreadable("negative expiry"))?;
    Ok(IssuedCode {
        tenant: TenantId::parse(row.tenant).map_err(|_| unreadable("tenant"))?,
        client_id: ClientId::parse(row.client_id).map_err(|_| unreadable("client_id"))?,
        redirect_uri: row.redirect_uri,
        challenge: Challenge::parse(row.challenge).map_err(|_| unreadable("challenge"))?,
        scopes: ScopeSet::parse(&row.scopes.join(" ")).map_err(|_| unreadable("scopes"))?,
        expires_at: Timestamp::from_unix_secs(seconds),
    })
}

impl CodeService {
    pub(crate) fn new(repository: Arc<dyn CodeRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Store `issued` under the digest of `code`. The code itself is never stored.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses — including a code that already exists at that digest.
    pub async fn issue(&self, code: &AuthorizationCode, issued: &IssuedCode) -> Result<()> {
        let place = self.tenancy.place(&issued.tenant)?;
        self.repository
            .create(&place, &code.digest(), &to_entity(issued)?)
            .await
    }

    /// Spend `code` in `tenant`, once.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses for a reason other than the code being spent, or holds a row this
    /// crate cannot read.
    pub async fn consume(
        &self,
        tenant: &TenantId,
        code: &AuthorizationCode,
        now: Timestamp,
    ) -> Result<Consumed> {
        let place = self.tenancy.place(tenant)?;
        let digest = code.digest();
        let at = i64::try_from(now.unix_secs()).map_err(|_| unreadable("time beyond i64"))?;
        match self.spend(&place, &digest, at).await {
            Ok(Some(before)) => Ok(Consumed::Fresh(to_model(before)?)),
            Ok(None) => Ok(Consumed::Absent),
            // Only the store saying no is answered by looking again. Anything else — the store unreachable, an
            // answer this crate cannot read — may have spent the code itself, and must never be told as a replay.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                match self.repository.find(&place, &digest).await? {
                    Some(row) if row.redeemed_at.is_some() => {
                        Ok(Consumed::Replayed(to_model(row)?))
                    }
                    Some(_) => Err(refusal),
                    None => Ok(Consumed::Absent),
                }
            }
            Err(failure) => Err(failure),
        }
    }

    /// The conditional spend, asked again while the store answers `retry` and attempts remain.
    async fn spend(&self, place: &Place, digest: &str, at: i64) -> Result<Option<CodeEntity>> {
        let mut pause = Duration::from_millis(CODE_SPEND_FIRST_PAUSE_MS);
        let mut attempt = 1;
        loop {
            let outcome = self.repository.mark_redeemed(place, digest, at).await;
            let retry = matches!(&outcome, Err(Error::Store(store)) if store.is_retry());
            if !retry || attempt >= CODE_SPEND_ATTEMPTS {
                return outcome;
            }
            tokio::time::sleep(pause).await;
            pause = pause.saturating_mul(2);
            attempt = attempt.saturating_add(1);
        }
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
