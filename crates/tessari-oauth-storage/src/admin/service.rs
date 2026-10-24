//! The admin service: a sign-in to the admin console leaves for the company issuer and is taken back once by the
//! browser that began it; the session it opens is found by its cookie, kept alive by the requests that find it and
//! ended once.
//!
//! Both records are keyed by the digest of a cookie, so a copy of either table opens nothing, and the `state` is kept
//! only as a digest. A session is not found once it has gone thirty minutes without a request or eight hours since its
//! sign-in, by this server's clock as well as the store's expiry. What the sign-in established is derived again from
//! the methods it verified, so a session never states a level its methods do not reach.

use std::sync::Arc;

use tessari_oauth_constants::{
    ADMIN_SESSION_ABSOLUTE_SECS, ADMIN_SESSION_IDLE_SECS, SIGNIN_WRITE_ATTEMPTS,
};
use tessari_oauth_core::authentication::{Method, assess};
use tessari_oauth_types::{
    Actor, ErrorCategory, IdempotencyKey, SessionSecret, SigninBinding, TenantId, Timestamp, UserId,
};

use super::repository::AdminRepository;
use super::{
    AdminActionEntity, AdminSession, AdminSessionEntity, Claim, PendingSignin, PendingSigninEntity,
};
use crate::{Error, Result, Tenancy, retry};

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "admin session",
        reason: reason.to_owned(),
    }
}

fn unix_secs(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| unreadable("time beyond i64"))
}

/// Whether a session signed in at `auth_time` and last found at `seen_at` is still alive at `now`.
fn alive(auth_time: i64, seen_at: i64, now: i64) -> Result<bool> {
    let idle = i64::try_from(ADMIN_SESSION_IDLE_SECS).map_err(|_| unreadable("idle"))?;
    let absolute =
        i64::try_from(ADMIN_SESSION_ABSOLUTE_SECS).map_err(|_| unreadable("absolute"))?;
    let idle_ends = seen_at
        .checked_add(idle)
        .ok_or_else(|| unreadable("seen_at"))?;
    let ends = auth_time
        .checked_add(absolute)
        .ok_or_else(|| unreadable("auth_time"))?;
    Ok(now < idle_ends && now < ends)
}

/// Admin console sign-ins and sessions in every company of a region.
pub struct AdminService {
    repository: Arc<dyn AdminRepository>,
    tenancy: Tenancy,
}

impl AdminService {
    pub(crate) fn new(repository: Arc<dyn AdminRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Record a sign-in to `tenant`'s admin console that the browser holding `binding` began at `now`, sending
    /// `state` and `nonce` and keeping `verifier` for the code.
    ///
    /// # Errors
    ///
    /// Store failures, including a refusal when the binding is already in use.
    pub async fn begin(
        &self,
        tenant: &TenantId,
        binding: &SigninBinding,
        state: &str,
        verifier: &str,
        nonce: &str,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let pending = PendingSigninEntity {
            state: SessionSecret::from_secret(state).digest(),
            verifier: verifier.to_owned(),
            nonce: nonce.to_owned(),
            created_at: unix_secs(now)?,
        };
        let id = binding.digest();
        retry::bounded(SIGNIN_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.begin(&place, &id, &pending)
        })
        .await
    }

    /// The sign-in the browser holding `binding` began in `tenant`, once; `None` for one never begun, already taken
    /// or lapsed.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn take(
        &self,
        tenant: &TenantId,
        binding: &SigninBinding,
    ) -> Result<Option<PendingSignin>> {
        let place = self.tenancy.place(tenant)?;
        let id = binding.digest();
        let taken = retry::take_once(
            SIGNIN_WRITE_ATTEMPTS,
            || self.repository.take(&place, &id),
            // A take the store refused is no sign-in: the browser starts again, and nothing is handed out twice.
            || async { Ok(false) },
        )
        .await?;
        Ok(taken.map(|kept| PendingSignin {
            state: kept.state,
            verifier: kept.verifier,
            nonce: kept.nonce,
        }))
    }

    /// Open an admin console session in `tenant` for `user`, who signed in at `now` with `methods` in the issuer
    /// session `sid`, under the browser's `secret`.
    ///
    /// # Errors
    ///
    /// Store failures, including a refusal when the secret is already in use.
    pub async fn open(
        &self,
        tenant: &TenantId,
        secret: &SessionSecret,
        user: &UserId,
        sid: &str,
        methods: &[Method],
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let signed_in = unix_secs(now)?;
        let session = AdminSessionEntity {
            user_id: user.as_str().to_owned(),
            sid: sid.to_owned(),
            methods: methods
                .iter()
                .map(|method| method.name().to_owned())
                .collect(),
            auth_time: signed_in,
            seen_at: signed_in,
        };
        let id = secret.digest();
        retry::bounded(SIGNIN_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.open(&place, &id, &session)
        })
        .await
    }

    /// The admin console session the browser holding `secret` has in `tenant` at `now`, when it is still alive;
    /// finding it keeps it alive.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn find(
        &self,
        tenant: &TenantId,
        secret: &SessionSecret,
        now: Timestamp,
    ) -> Result<Option<AdminSession>> {
        let place = self.tenancy.place(tenant)?;
        let id = secret.digest();
        let Some(kept) = self.repository.find(&place, &id).await? else {
            return Ok(None);
        };
        let now_secs = unix_secs(now)?;
        if !alive(kept.auth_time, kept.seen_at, now_secs)? {
            return Ok(None);
        }
        let methods = kept
            .methods
            .iter()
            .map(|name| Method::named(name).ok_or_else(|| unreadable("methods")))
            .collect::<Result<Vec<_>>>()?;
        let assessment = assess(&methods).ok_or_else(|| unreadable("methods"))?;
        let user = UserId::parse(kept.user_id).map_err(|_| unreadable("user_id"))?;
        let auth_time = u64::try_from(kept.auth_time).map_err(|_| unreadable("auth_time"))?;
        match self.repository.touch(&place, &id, now_secs).await {
            // A request in the same second, or a later one, already moved it at least this far.
            Ok(()) | Err(Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {}
            Err(failure) => return Err(failure),
        }
        Ok(Some(AdminSession {
            user,
            sid: kept.sid,
            auth_time: Timestamp::from_unix_secs(auth_time),
            methods,
            assessment,
        }))
    }

    /// End the admin console session under `secret` in `tenant`, once; `false` when there was none.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn end(&self, tenant: &TenantId, secret: &SessionSecret) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let id = secret.digest();
        let taken = retry::take_once(
            SIGNIN_WRITE_ATTEMPTS,
            || self.repository.end(&place, &id),
            || async { Ok(self.repository.find(&place, &id).await?.is_some()) },
        )
        .await?;
        Ok(taken.is_some())
    }

    /// Claim `operator`'s change `action`, sent with the request digest `request` under `key` in `tenant` at `now`.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn claim(
        &self,
        tenant: &TenantId,
        operator: &Actor,
        key: &IdempotencyKey,
        action: &str,
        request: &str,
        now: Timestamp,
    ) -> Result<Claim> {
        let place = self.tenancy.place(tenant)?;
        let id = key.record_id(operator);
        let claimed = AdminActionEntity {
            operator: operator.name(),
            action: action.to_owned(),
            request: request.to_owned(),
            status: None,
            answer: None,
            created_at: unix_secs(now)?,
        };
        match self.repository.claim(&place, &id, &claimed).await {
            Ok(()) => return Ok(Claim::Fresh),
            // Claimed before: what it holds decides.
            Err(refused) if refused.category() == ErrorCategory::Conflict => {}
            Err(failure) => return Err(failure),
        }
        let Some(kept) = self.repository.action(&place, &id).await? else {
            // Released or lapsed between the two reads: the earlier change is not standing in the way.
            return Ok(Claim::InFlight);
        };
        if kept.operator != claimed.operator || kept.action != action || kept.request != request {
            return Ok(Claim::Reused);
        }
        Ok(match (kept.status, kept.answer) {
            (Some(status), Some(answer)) => Claim::Answered {
                status: u16::try_from(status).map_err(|_| unreadable("status"))?,
                answer,
            },
            _ => Claim::InFlight,
        })
    }

    /// Record that `operator`'s change under `key` in `tenant` was answered with `status` and `answer`.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn finish(
        &self,
        tenant: &TenantId,
        operator: &Actor,
        key: &IdempotencyKey,
        status: u16,
        answer: &str,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .finish(&place, &key.record_id(operator), i64::from(status), answer)
            .await
    }

    /// Give back `operator`'s claim under `key` in `tenant` for a change that was not made, so it may be sent again.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn release(
        &self,
        tenant: &TenantId,
        operator: &Actor,
        key: &IdempotencyKey,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .release(&place, &key.record_id(operator))
            .await
    }
}
