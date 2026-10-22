//! The session service: a user's session at this issuer, created at sign-in, found by its cookie, kept alive by the
//! requests that find it and ended once.
//!
//! The record's id is the digest of the session cookie's value, so a copy of the table opens nothing. A session is
//! not found once it has gone a working day without a request or a week since its sign-in, by this server's clock as
//! well as the store's expiry. Its public id is drawn apart, so naming a session to a client says nothing about the
//! cookie that holds it. What the sign-in established is derived again from the methods it verified, so a
//! session never states a level its methods do not reach.

use std::sync::Arc;

use tessari_oauth_constants::{SESSION_ABSOLUTE_SECS, SESSION_IDLE_SECS, SIGNIN_WRITE_ATTEMPTS};
use tessari_oauth_core::authentication::{Method, assess};
use tessari_oauth_infrastructure::custody::token_id;
use tessari_oauth_types::{SessionSecret, TenantId, Timestamp, UserId};

use super::entity::ListedSessionEntity;
use super::repository::SessionRepository;
use super::{ListedSession, Session, SessionEntity};
use crate::{Error, Result, Tenancy, answers, retry};

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "session",
        reason: reason.to_owned(),
    }
}

fn unix_secs(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| unreadable("time beyond i64"))
}

/// Whether a session signed in at `auth_time` and last found at `seen_at` is still alive at `now`.
fn alive(auth_time: i64, seen_at: i64, now: i64) -> Result<bool> {
    let idle = i64::try_from(SESSION_IDLE_SECS).map_err(|_| unreadable("idle"))?;
    let absolute = i64::try_from(SESSION_ABSOLUTE_SECS).map_err(|_| unreadable("absolute"))?;
    let idle_ends = seen_at
        .checked_add(idle)
        .ok_or_else(|| unreadable("seen_at"))?;
    let ends = auth_time
        .checked_add(absolute)
        .ok_or_else(|| unreadable("auth_time"))?;
    Ok(now < idle_ends && now < ends)
}

/// Sessions at this issuer.
#[derive(Clone)]
pub struct SessionService {
    repository: Arc<dyn SessionRepository>,
    tenancy: Tenancy,
}

impl SessionService {
    pub(crate) fn new(repository: Arc<dyn SessionRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Open a session for `user`, signed in at `now` with `methods`, under the browser's `secret` in `tenant`.
    ///
    /// # Errors
    ///
    /// Store failures, including a refusal when the secret is already in use.
    pub async fn create(
        &self,
        tenant: &TenantId,
        secret: &SessionSecret,
        user: &UserId,
        methods: &[Method],
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let id = secret.digest();
        let signed_in = unix_secs(now)?;
        let session = SessionEntity {
            user_id: user.as_str().to_owned(),
            sid: token_id()?,
            methods: methods
                .iter()
                .map(|method| method.name().to_owned())
                .collect(),
            auth_time: signed_in,
            seen_at: signed_in,
        };
        retry::bounded(SIGNIN_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.create(&place, &id, &session)
        })
        .await
    }

    /// The session the browser holding `secret` has in `tenant` at `now`, when it is still alive; finding it keeps
    /// it alive.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn find(
        &self,
        tenant: &TenantId,
        secret: &SessionSecret,
        now: Timestamp,
    ) -> Result<Option<Session>> {
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
        Ok(Some(Session {
            user,
            sid: kept.sid,
            methods,
            auth_time: Timestamp::from_unix_secs(auth_time),
            assessment,
        }))
    }

    /// End the session under `secret`, once; `false` when there was none.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn end(&self, tenant: &TenantId, secret: &SessionSecret) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let id = secret.digest();
        let taken = retry::take_once(
            SIGNIN_WRITE_ATTEMPTS,
            || self.repository.take(&place, &id),
            || async { Ok(self.repository.find(&place, &id).await?.is_some()) },
        )
        .await?;
        Ok(taken.is_some())
    }

    /// The sessions of `user` in `tenant` still alive at `now`, oldest sign-in first.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn list(
        &self,
        tenant: &TenantId,
        user: &UserId,
        now: Timestamp,
    ) -> Result<Vec<ListedSession>> {
        let place = self.tenancy.place(tenant)?;
        let now_secs = unix_secs(now)?;
        let mut listed = Vec::new();
        for ListedSessionEntity { session, .. } in
            self.repository.list_for_user(&place, user.as_str()).await?
        {
            if !alive(session.auth_time, session.seen_at, now_secs)? {
                continue;
            }
            listed.push(ListedSession {
                auth_time: Timestamp::from_unix_secs(
                    u64::try_from(session.auth_time).map_err(|_| unreadable("auth_time"))?,
                ),
                seen_at: Timestamp::from_unix_secs(
                    u64::try_from(session.seen_at).map_err(|_| unreadable("seen_at"))?,
                ),
                methods: session
                    .methods
                    .iter()
                    .map(|name| Method::named(name).ok_or_else(|| unreadable("methods")))
                    .collect::<Result<Vec<_>>>()?,
                sid: session.sid,
            });
        }
        listed.sort_by_key(|session| session.auth_time.unix_secs());
        Ok(listed)
    }

    /// End `user`'s session in `tenant` whose public id is `sid`, once; `false` when `user` has none by that id.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record id this service did not write.
    pub async fn end_sid(&self, tenant: &TenantId, user: &UserId, sid: &str) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let held = self.repository.list_for_user(&place, user.as_str()).await?;
        let Some(found) = held.into_iter().find(|listed| listed.session.sid == sid) else {
            return Ok(false);
        };
        let id = answers::text_id(&found.spelled, "session")?;
        Ok(self.repository.take(&place, &id).await?.is_some())
    }

    /// End every session of `user` in `tenant` but the one whose public id is `except`, answering how many of them
    /// were still alive at `now`.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn end_all(
        &self,
        tenant: &TenantId,
        user: &UserId,
        except: Option<&str>,
        now: Timestamp,
    ) -> Result<usize> {
        let place = self.tenancy.place(tenant)?;
        let now_secs = unix_secs(now)?;
        // The store deletes many records only one by one, each by its id: read the user's, then end each.
        let mut ended = 0_usize;
        for listed in self.repository.list_for_user(&place, user.as_str()).await? {
            if except == Some(listed.session.sid.as_str()) {
                continue;
            }
            let id = answers::text_id(&listed.spelled, "session")?;
            let Some(taken) = self.repository.take(&place, &id).await? else {
                continue;
            };
            if alive(taken.auth_time, taken.seen_at, now_secs)? {
                ended = ended.checked_add(1).ok_or_else(|| unreadable("count"))?;
            }
        }
        Ok(ended)
    }
}
