//! `GET|POST /{tenant}/oauth2/userinfo` (OpenID Connect Core §5.3): the subject an access token speaks for.
//!
//! The token is read from the `Authorization` header alone and judged by the core as a resource server judges one;
//! the answer is the token's subject and nothing more until the user directory and the claims policy exist. A refusal
//! is a challenge in `WWW-Authenticate` (RFC 6750 §3, RFC 9449 §7.1) whose `error` is the one code the caller needs,
//! the same for every kind of bad token, while the precise reason goes to the audit trail. A bound token's proof is
//! spent only once everything else held. No answer may be stored by a cache.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_constants::{OPENID_SCOPE, USERINFO_PATH};
use tessari_oauth_core::Reason;
use tessari_oauth_core::jose::VerifyingKey;
use tessari_oauth_core::keys::{self, KeyRecord};
use tessari_oauth_core::token::Refusal;
use tessari_oauth_core::userinfo::{self, Expected, Presented};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::replay::Spent;
use tessari_oauth_types::{ErrorCode, TenantId, Timestamp};

use crate::Error;
use crate::headers::no_store;
use crate::state::PublicState;

/// The answer: whom the token speaks for.
#[derive(Serialize)]
struct Answer {
    sub: String,
}

/// The two schemes a token may arrive under.
#[derive(Clone, Copy)]
enum Scheme {
    Bearer,
    Dpop,
}

impl Scheme {
    const fn name(self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::Dpop => "DPoP",
        }
    }
}

pub(super) async fn userinfo(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> crate::Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let issuer = &*issuer;
    let now = (state.clock)();
    let Some((scheme, token)) = credentials(&headers) else {
        let missing = Refusal {
            error: ErrorCode::InvalidToken,
            reason: Reason::AccessTokenMissing,
        };
        return refuse(&state, &tenant, Scheme::Bearer, missing, now).await;
    };
    let mut proofs = headers.get_all("dpop").iter();
    let proof = match (proofs.next(), proofs.next()) {
        (Some(_), Some(_)) => {
            let several = Refusal {
                error: ErrorCode::InvalidDpopProof,
                reason: Reason::DpopSeveralProofs,
            };
            return refuse(&state, &tenant, scheme, several, now).await;
        }
        (proof, _) => proof.and_then(|value| value.to_str().ok()),
    };
    let presented = match scheme {
        Scheme::Bearer => Presented::Bearer(token),
        Scheme::Dpop => Presented::Dpop { token, proof },
    };
    let keys = published_keys(&state, &tenant, now).await?;
    let audience = format!("{issuer}{USERINFO_PATH}");
    let expected = Expected {
        issuer,
        audience: &audience,
        algorithm: state.signing_algorithm,
        keys: &keys,
        method: method.as_str(),
        target: &audience,
    };
    let access = match userinfo::verify(presented, &expected, now) {
        Ok(access) => access,
        Err(refused) => return refuse(&state, &tenant, scheme, refused, now).await,
    };
    if let Some(proof) = &access.proof {
        let spent = state
            .replay
            .spend_proof(&tenant, proof, now)
            .await
            .map_err(Error::Store)?;
        if spent == Spent::Replayed {
            let replayed = Refusal {
                error: ErrorCode::InvalidDpopProof,
                reason: Reason::DpopReplayed,
            };
            return refuse(&state, &tenant, scheme, replayed, now).await;
        }
    }
    Ok(no_store(
        Json(Answer {
            sub: access.subject,
        })
        .into_response(),
    ))
}

/// The scheme and token of the one `Authorization` header, when it is `Bearer` or `DPoP` (case-insensitive, RFC 9110
/// §11.1) followed by a single token.
fn credentials(headers: &HeaderMap) -> Option<(Scheme, &str)> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let (name, token) = value.to_str().ok()?.split_once(' ')?;
    let scheme = if name.eq_ignore_ascii_case("bearer") {
        Scheme::Bearer
    } else if name.eq_ignore_ascii_case("dpop") {
        Scheme::Dpop
    } else {
        return None;
    };
    (!token.is_empty() && !token.contains(' ')).then_some((scheme, token))
}

/// The verifying keys `tenant` publishes now, under the algorithm the server signs with.
pub(super) async fn published_keys(
    state: &PublicState,
    tenant: &TenantId,
    now: Timestamp,
) -> crate::Result<Vec<VerifyingKey>> {
    let stored = state.keys.live(tenant).await.map_err(Error::Store)?;
    let records: Vec<KeyRecord> = stored
        .iter()
        .map(|key| KeyRecord {
            kid: key.kid.clone(),
            created_at: key.created_at,
            compromised: key.compromised,
        })
        .collect();
    let plan = keys::plan(&records, now);
    Ok(stored
        .iter()
        .filter(|key| key.algorithm == state.signing_algorithm && plan.published.contains(&key.kid))
        .filter_map(|key| VerifyingKey::from_jwk(&key.public_jwk, key.algorithm).ok())
        .collect())
}

/// Record `refused`, then answer it with its challenge under `scheme`.
async fn refuse(
    state: &PublicState,
    tenant: &TenantId,
    scheme: Scheme,
    refused: Refusal,
    now: Timestamp,
) -> crate::Result<Response> {
    tracing::warn!(
        event = "userinfo_refused",
        tenant = tenant.as_str(),
        reason = ?refused.reason,
        error = refused.error.as_str(),
        "a UserInfo request was refused"
    );
    let event = AuditEvent {
        reason: Some(format!("{:?}", refused.reason)),
        ..AuditEvent::of(AuditKind::Refused)
    };
    if let Err(failure) = state.audit.record(tenant, &event, now).await {
        tracing::error!(
            event = "audit_unrecorded",
            tenant = tenant.as_str(),
            category = ?failure.category(),
            "a refusal could not be appended to the audit trail"
        );
    }
    let (status, challenge) = match (refused.reason, refused.error) {
        // No credentials of a known scheme: the bare challenge, with no error code (RFC 6750 §3.1).
        (Reason::AccessTokenMissing, _) => (StatusCode::UNAUTHORIZED, scheme.name().to_owned()),
        (_, ErrorCode::InsufficientScope) => (
            StatusCode::FORBIDDEN,
            format!(
                r#"{} error="insufficient_scope", scope="{OPENID_SCOPE}""#,
                scheme.name()
            ),
        ),
        (_, error) => (
            StatusCode::UNAUTHORIZED,
            format!(r#"{} error="{}""#, scheme.name(), error.as_str()),
        ),
    };
    let challenge = HeaderValue::from_str(&challenge).map_err(|_| Error::Internal)?;
    Ok(no_store(
        (status, [(header::WWW_AUTHENTICATE, challenge)]).into_response(),
    ))
}
