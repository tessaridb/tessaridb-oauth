//! `POST /{tenant}/account/api/me/verify`: the signed-in user asks for a link that verifies the address their account
//! signs in with. An address already verified gets no mail (`204`); otherwise one link is mailed to it (`202`), and a
//! newer request replaces the older link. Without a relay the request answers `503` with `mail_unavailable`.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::login::{send_verification, signed_in};
use crate::state::PublicState;
use crate::{Error, Result};

pub(super) async fn request(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let now = (state.clock)();
    let user = signed_in(&state, &tenant, &headers, now).await?.user;
    if !state.mail {
        return Err(Error::MailUnavailable);
    }
    // A session names an account that existed when it signed in, and accounts are never removed.
    let account = state
        .users
        .find(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Internal)?;
    if account.email_verified {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    send_verification(&state, &tenant, &issuer, &user, &account.email, now).await?;
    Ok(StatusCode::ACCEPTED.into_response())
}
