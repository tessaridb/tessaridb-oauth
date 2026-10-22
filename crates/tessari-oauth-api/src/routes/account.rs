//! `/{tenant}/account/api/grants`: the signed-in user's own grants, and the way to end one.
//!
//! Both need the session this issuer opened for the browser, and act for that session's user alone: no request names
//! whose grants it reads or ends. The list shows the grants that stand. Ending one ends the consent, records who
//! ended it, then revokes every refresh family of that user at that client, and answers when the access tokens
//! already issued under it stop working, because a self-contained token cannot be recalled before it expires. A
//! grant that does not stand is answered as not ended and nothing changes. Bodies are JSON, which a cross-site form
//! cannot send, and the session cookie is `SameSite=Lax`, which a cross-site POST does not carry. No answer may be
//! stored by a cache.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::ACCESS_TOKEN_TTL_SECS;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::consents::Revoker;
use tessari_oauth_storage::refresh::Holder;
use tessari_oauth_types::ClientId;

use super::login::{body, record, signed_in};
use crate::state::PublicState;
use crate::{Error, Result};

/// The reason the refresh families of an ended grant are revoked for.
const CONSENT_REVOKED: &str = "consent_revoked";

/// One grant as the list shows it.
#[derive(Serialize)]
struct Grant {
    client_id: String,
    scopes: Vec<String>,
    resources: Vec<String>,
    granted_at: u64,
}

#[derive(Serialize)]
struct Grants {
    grants: Vec<Grant>,
}

#[derive(Deserialize)]
pub(super) struct Ending {
    client_id: String,
}

/// What ending a grant did.
#[derive(Serialize)]
struct Ended {
    revoked: bool,
    families: usize,
    access_tokens_end_by: u64,
}

pub(super) async fn grants(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let now = (state.clock)();
    let session = signed_in(&state, &tenant, &headers, now).await?;
    let grants = state
        .consents
        .list(&tenant, &session.user)
        .await
        .map_err(Error::Store)?
        .into_iter()
        .filter(|consent| consent.revoked.is_none())
        .map(|consent| Grant {
            client_id: consent.client_id.as_str().to_owned(),
            scopes: consent.scopes.iter().map(str::to_owned).collect(),
            resources: consent
                .resources
                .iter()
                .map(|resource| resource.as_str().to_owned())
                .collect(),
            granted_at: consent.granted_at.unix_secs(),
        })
        .collect();
    Ok((StatusCode::OK, Json(Grants { grants })).into_response())
}

pub(super) async fn revoke(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Ending>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let ending = body(read)?;
    let now = (state.clock)();
    let session = signed_in(&state, &tenant, &headers, now).await?;
    let client = ClientId::parse(&ending.client_id).map_err(|_| Error::Invalid)?;
    let user = session.user;
    let revoked = state
        .consents
        .revoke(&tenant, &user, &client, &Revoker::User, now)
        .await
        .map_err(Error::Store)?;
    let families = if revoked {
        let event = AuditEvent {
            client_id: Some(client.clone()),
            user: Some(user.clone()),
            reason: Some("user".to_owned()),
            ..AuditEvent::of(AuditKind::ConsentRevoked)
        };
        record(&state, &tenant, &event, now).await;
        let holder = Holder::Grant {
            user: &user,
            client: &client,
        };
        state
            .refresh
            .revoke_standing(&tenant, &holder, CONSENT_REVOKED, now)
            .await
            .map_err(Error::Store)?
    } else {
        0
    };
    let access_tokens_end_by = now
        .unix_secs()
        .checked_add(ACCESS_TOKEN_TTL_SECS)
        .ok_or(Error::Internal)?;
    let ended = Ended {
        revoked,
        families,
        access_tokens_end_by,
    };
    Ok((StatusCode::OK, Json(ended)).into_response())
}
