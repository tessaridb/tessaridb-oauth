//! A console change: from the console's own origin, by an operator holding the role it needs, with the operator's
//! reason and an `Idempotency-Key`. The change is made once per operator and key; sent again it is answered as it was
//! answered the first time, and every answer is recorded with who made the change, under which role, and why.

use std::future::Future;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tessari_oauth_constants::ADMIN_REASON_MAX_CHARS;
use tessari_oauth_storage::admin::Claim;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{IdempotencyKey, UserId, request_digest};

use super::AdminState;
use super::operator::{Operator, from_console, signed_in};
use crate::{Error, Result};

/// A change's request body, which carries the operator's reason.
pub(super) trait Reasoned {
    /// The operator's reason, as sent.
    fn reason(&self) -> &str;
}

/// What making a change answered: the status and the JSON body, and the user it concerned when it concerned one.
pub(super) struct Made {
    pub(super) status: StatusCode,
    pub(super) body: String,
    pub(super) user: Option<UserId>,
}

/// A change refused by what it found, in the shape every refusal has, kept as the change's answer.
#[derive(Serialize)]
pub(super) struct Refusal {
    pub(super) code: &'static str,
    pub(super) message: &'static str,
}

/// Make the change `action`, which needs `role`, from the request `headers` and `body` at `company`'s console, by
/// `make`, once per operator and `Idempotency-Key`.
pub(super) async fn apply<T, F, Fut>(
    state: &AdminState,
    (company, headers, body): (&str, &HeaderMap, &[u8]),
    (role, action): (OperatorRole, &'static str),
    make: F,
) -> Result<Response>
where
    T: DeserializeOwned + Reasoned,
    F: FnOnce(Operator, T) -> Fut,
    Fut: Future<Output = Result<Made>>,
{
    from_console(state, headers)?;
    let operator = signed_in(state, company, headers).await?;
    operator.require(state, role, action).await?;
    let sent: T = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
    let reason = sent.reason().trim().to_owned();
    if reason.is_empty() || reason.chars().count() > ADMIN_REASON_MAX_CHARS {
        return Err(Error::ReasonRequired);
    }
    let key = headers
        .get("idempotency-key")
        .and_then(|key| key.to_str().ok())
        .and_then(|key| IdempotencyKey::parse(key).ok())
        .ok_or(Error::IdempotencyKeyRequired)?;
    let (tenant, actor) = (operator.tenant.clone(), operator.user.clone());
    let now = (state.clock)();
    match state
        .admin
        .claim(&tenant, &actor, &key, action, &request_digest(body), now)
        .await
        .map_err(Error::Store)?
    {
        Claim::Fresh => {}
        Claim::Answered { status, answer } => {
            let status = StatusCode::from_u16(status).map_err(|_| Error::Internal)?;
            return answered(status, answer);
        }
        Claim::InFlight => return Err(Error::ChangeInProgress),
        Claim::Reused => return Err(Error::IdempotencyKeyReused),
    }
    let made = match make(operator, sent).await {
        Ok(made) => made,
        Err(failure) => {
            // Not made: the key is given back, so the same change may be sent again.
            if let Err(release) = state.admin.release(&tenant, &actor, &key).await {
                tracing::error!(
                    event = "idempotency_unreleased",
                    tenant = tenant.as_str(),
                    category = ?release.category(),
                    "a change that was not made could not give its key back"
                );
            }
            return Err(failure);
        }
    };
    if let Err(unkept) = state
        .admin
        .finish(&tenant, &actor, &key, made.status.as_u16(), &made.body)
        .await
    {
        // The change stands; only a repeat of it can no longer be answered from the record.
        tracing::error!(
            event = "idempotency_unkept",
            tenant = tenant.as_str(),
            category = ?unkept.category(),
            "a change was made but its answer could not be kept"
        );
    }
    state
        .record(
            &tenant,
            &AuditEvent {
                actor: Some(actor.as_str().to_owned()),
                user: made.user,
                role: Some(role),
                action: Some(action.to_owned()),
                reason: Some(reason),
                ..AuditEvent::of(AuditKind::AdminAction)
            },
        )
        .await;
    answered(made.status, made.body)
}

/// The answer `status` with the JSON `body`.
fn answered(status: StatusCode, body: String) -> Result<Response> {
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}
