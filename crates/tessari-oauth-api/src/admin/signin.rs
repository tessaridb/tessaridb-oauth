//! Leaving for the company issuer: `GET /admin/{company}/signin` keeps a sign-in for this browser under a fresh
//! sign-in cookie and sends the browser to the company's authorization endpoint as `admin-console`, with a PKCE S256
//! challenge, a `state` and a `nonce`, asking for `openid` and redirected back only to the console's callback.
//!
//! The cookie is `SameSite=Lax`: the browser comes back from the issuer by a top-level navigation from another origin,
//! which a `Strict` cookie would not survive. It is `__Host-` and `Secure` when the console is reached over https and
//! carries neither on a console served in the clear, which configuration allows only on a loopback address.

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tessari_oauth_constants::{ADMIN_CONSOLE_CLIENT, ADMIN_SIGNIN_TTL_SECS, OPENID_SCOPE};
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_types::{Challenge, SigninBinding, TenantId, base64url};
use url::Url;

use super::{AdminState, SIGNIN_COOKIE};
use crate::{Error, Result};

/// 256 bits from the system's cryptographic random source, base64url.
pub(super) fn fresh() -> Result<String> {
    let drawn = random_secret().map_err(|_| Error::Internal)?;
    Ok(base64url::encode(&drawn))
}

/// Keep a sign-in for this browser and send it to `company`'s issuer; an unknown or inactive company answers 404.
pub(super) async fn signin(
    State(state): State<AdminState>,
    Path(company): Path<String>,
) -> Result<Response> {
    let tenant = TenantId::parse(&company).map_err(|_| Error::NotFound)?;
    let issuer = state.served.issuer(&tenant).ok_or(Error::NotFound)?;
    let binding = SigninBinding::from_secret(fresh()?);
    let (sent, nonce, verifier) = (fresh()?, fresh()?, fresh()?);
    let challenge = Challenge::of(&verifier).map_err(|_| Error::Internal)?;
    state
        .admin
        .begin(&tenant, &binding, &sent, &verifier, &nonce, (state.clock)())
        .await
        .map_err(Error::Store)?;
    let mut location =
        Url::parse(&format!("{issuer}/oauth2/authorize")).map_err(|_| Error::Internal)?;
    location
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", ADMIN_CONSOLE_CLIENT)
        .append_pair(
            "redirect_uri",
            &format!("{}/admin/{}/callback", state.console, tenant.as_str()),
        )
        .append_pair("scope", OPENID_SCOPE)
        .append_pair("state", &sent)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", challenge.as_str())
        .append_pair("code_challenge_method", "S256");
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(location.as_str()).map_err(|_| Error::Internal)?,
    );
    headers.insert(
        header::SET_COOKIE,
        state.cookie(
            SIGNIN_COOKIE,
            binding.expose(),
            "Lax",
            ADMIN_SIGNIN_TTL_SECS,
        )?,
    );
    Ok(response)
}
