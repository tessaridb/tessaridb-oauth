//! Coming back from the company issuer: `GET /admin/{company}/callback` takes the sign-in this browser began, once, and
//! opens a console session only when every check holds: the `state` it sent, the issuer it left for (RFC 9207), the
//! code spent once and checked by the same bindings the token endpoint checks, the `nonce` it sent, a sign-in with two
//! factors, and at least one current operator grant.
//!
//! Every answer after the take clears the sign-in cookie. Every refusal answers alike, opens nothing and is audited
//! with its reason, so the browser learns nothing about which check failed.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tessari_oauth_constants::{ADMIN_CONSOLE_CLIENT, ADMIN_SESSION_ABSOLUTE_SECS};
use tessari_oauth_core::Params;
use tessari_oauth_core::authentication::{Level, assess};
use tessari_oauth_core::codes::IssuedCode;
use tessari_oauth_core::token;
use tessari_oauth_storage::admin::PendingSignin;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::codes::Consumed;
use tessari_oauth_types::{
    AuthorizationCode, ClientId, SessionSecret, SigninBinding, TenantId, Timestamp,
};

use super::signin::fresh;
use super::{AdminState, SESSION_COOKIE, SIGNIN_COOKIE};
use crate::routes::cookie;
use crate::{Error, Result};

type Pairs = Vec<(String, String)>;

/// Finish the sign-in this browser began at `company`'s console, or refuse it.
pub(super) async fn callback(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    pairs: std::result::Result<Query<Pairs>, QueryRejection>,
) -> Result<Response> {
    let tenant = TenantId::parse(&company).map_err(|_| Error::NotFound)?;
    let issuer = state.served.issuer(&tenant).ok_or(Error::NotFound)?;
    let binding = cookie(&headers, &state.cookie_name(SIGNIN_COOKIE))
        .map(SigninBinding::from_secret)
        .ok_or(Error::SigninGone)?;
    let pending = state
        .admin
        .take(&tenant, &binding)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SigninGone)?;
    let now = (state.clock)();
    let returned = Return {
        state: &state,
        tenant: &tenant,
        issuer: &issuer,
        now,
    };
    let mut response = match returned
        .finish(&pending, pairs.map(|Query(pairs)| pairs).ok())
        .await
    {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    };
    response.headers_mut().append(
        header::SET_COOKIE,
        state.cookie(SIGNIN_COOKIE, "", "Lax", 0)?,
    );
    Ok(response)
}

/// One browser's return to the console of `tenant`, whose issuer is `issuer`, judged at `now`.
struct Return<'a> {
    state: &'a AdminState,
    tenant: &'a TenantId,
    issuer: &'a str,
    now: Timestamp,
}

impl Return<'_> {
    /// Every check in order, then the session; the first that fails refuses.
    async fn finish(&self, pending: &PendingSignin, pairs: Option<Pairs>) -> Result<Response> {
        let Some(params) = pairs.and_then(|pairs| Params::from_pairs(pairs).ok()) else {
            return Err(self.refuse("callback_unreadable", None).await);
        };
        if !params
            .get("state")
            .is_some_and(|sent| pending.state_matches(sent))
        {
            return Err(self.refuse("state_mismatch", None).await);
        }
        if params.get("iss") != Some(self.issuer) {
            return Err(self.refuse("issuer_mismatch", None).await);
        }
        let Some(code) = params.get("code").map(AuthorizationCode::from_secret) else {
            return Err(self.refuse("code_missing", None).await);
        };
        let issued = self.spend(&code).await?;
        self.check(pending, &issued).await?;
        let secret = SessionSecret::from_secret(fresh()?);
        let authentication = &issued.authentication;
        self.state
            .admin
            .open(
                self.tenant,
                &secret,
                &issued.user,
                &authentication.sid,
                &authentication.methods,
                self.now,
            )
            .await
            .map_err(Error::Store)?;
        self.record(&AuditEvent {
            client_id: Some(console_client()?),
            user: Some(issued.user.clone()),
            ..AuditEvent::of(AuditKind::ConsoleSignedIn)
        })
        .await;
        let mut response = StatusCode::SEE_OTHER.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::LOCATION,
            format!("/admin/{}/", self.tenant.as_str())
                .parse()
                .map_err(|_| Error::Internal)?,
        );
        // Strict: the panel reads it by same-origin requests only, so no other site's navigation ever carries it.
        headers.insert(
            header::SET_COOKIE,
            self.state.cookie(
                SESSION_COOKIE,
                secret.expose(),
                "Strict",
                ADMIN_SESSION_ABSOLUTE_SECS,
            )?,
        );
        Ok(response)
    }

    /// The code spent once; an unknown code or one already spent refuses.
    async fn spend(&self, code: &AuthorizationCode) -> Result<IssuedCode> {
        match self
            .state
            .codes
            .consume(self.tenant, code, self.now)
            .await
            .map_err(Error::Store)?
        {
            Consumed::Fresh(issued) => Ok(issued),
            Consumed::Absent => Err(self.refuse("code_unknown", None).await),
            Consumed::Replayed(issued) => {
                // The console starts no refresh family and mints no token, so a replay has nothing to revoke; it says
                // the code leaked.
                tracing::warn!(
                    event = "code_replayed",
                    tenant = self.tenant.as_str(),
                    client = ADMIN_CONSOLE_CLIENT,
                    "a redeemed code was presented again at the admin console"
                );
                self.record(&AuditEvent {
                    client_id: Some(console_client()?),
                    user: Some(issued.user),
                    ..AuditEvent::of(AuditKind::CodeReplayed)
                })
                .await;
                Err(Error::ConsoleRefused)
            }
        }
    }

    /// The code's bindings as the token endpoint checks them, then what the console itself asks of the sign-in.
    async fn check(&self, pending: &PendingSignin, issued: &IssuedCode) -> Result<()> {
        let client_id = console_client()?;
        let Some(client) = self
            .state
            .clients
            .find(self.tenant, &client_id)
            .await
            .map_err(Error::Store)?
        else {
            return Err(self.refuse("console_unregistered", None).await);
        };
        let redirect_uri = format!(
            "{}/admin/{}/callback",
            self.state.console,
            self.tenant.as_str()
        );
        let params = Params::from_pairs([
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ])
        .map_err(|_| Error::Internal)?;
        if let Err(refusal) = token::redeem_code(self.tenant, &client, &params, issued, self.now) {
            return Err(self
                .refuse(&format!("{:?}", refusal.reason), Some(issued))
                .await);
        }
        if issued.nonce.as_deref() != Some(pending.nonce.as_str()) {
            return Err(self.refuse("nonce_mismatch", Some(issued)).await);
        }
        let two_factors = assess(&issued.authentication.methods)
            .is_some_and(|assessment| assessment.level >= Level::MultiFactor);
        if !two_factors {
            return Err(self.refuse("single_factor", Some(issued)).await);
        }
        let grants = self
            .state
            .operators
            .grants(self.tenant, &issued.user, self.now)
            .await
            .map_err(Error::Store)?;
        if grants.is_empty() {
            return Err(self.refuse("no_operator_grant", Some(issued)).await);
        }
        Ok(())
    }

    /// Log and audit a refusal for `reason`, naming the user of `issued` when the code was read, and answer it.
    async fn refuse(&self, reason: &str, issued: Option<&IssuedCode>) -> Error {
        tracing::warn!(
            event = "console_signin_refused",
            tenant = self.tenant.as_str(),
            reason,
            "a return to the admin console was refused"
        );
        let Ok(client_id) = console_client() else {
            return Error::Internal;
        };
        self.record(&AuditEvent {
            client_id: Some(client_id),
            user: issued.map(|issued| issued.user.clone()),
            reason: Some(reason.to_owned()),
            ..AuditEvent::of(AuditKind::Refused)
        })
        .await;
        Error::ConsoleRefused
    }

    /// Append `event` to the trail; a trail that does not take it is logged, never answered.
    async fn record(&self, event: &AuditEvent) {
        if let Err(failure) = self.state.audit.record(self.tenant, event, self.now).await {
            tracing::error!(
                event = "audit_unrecorded",
                tenant = self.tenant.as_str(),
                category = ?failure.category(),
                "an admin console event could not be appended to the audit trail"
            );
        }
    }
}

/// The console's client id.
fn console_client() -> Result<ClientId> {
    ClientId::parse(ADMIN_CONSOLE_CLIENT).map_err(|_| Error::Internal)
}
