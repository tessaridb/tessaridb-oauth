//! `POST /{tenant}/login/api/begin`: start signing in for a pending authorization, or for the account page.
//!
//! The body names exactly one of the two: `{"interaction": "<id>"}` or `{"account": true}`; anything else is
//! refused. An authorization must still be pending (kept, brought by this browser as its browser cookie says, and
//! within its lifetime), or nothing is started and no cookie is set. A sign-in for the account page answers no
//! authorization: once complete it opens a session and continues to the account page. A started sign-in is bound
//! to a fresh value the server draws and sets as the sign-in cookie; beginning again starts a new one under a new
//! value, and the old one lapses on its own.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use tessari_oauth_core::ceremony::Stage;
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::signins::Purpose;
use tessari_oauth_types::{SigninBinding, base64url};

use super::super::browser::held;
use super::{answer, binding_cookie, body, well_formed};
use crate::state::PublicState;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(in crate::routes) struct Begin {
    interaction: Option<String>,
    #[serde(default)]
    account: bool,
}

pub(in crate::routes) async fn begin(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Begin>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let now = (state.clock)();
    let purpose = match body(read)? {
        Begin {
            interaction: Some(interaction),
            account: false,
        } => {
            let Some(browser) = held(&headers).filter(|_| well_formed(&interaction)) else {
                return Err(Error::SigninGone);
            };
            state
                .interactions
                .find(&tenant, &interaction, &browser, now)
                .await
                .map_err(Error::Store)?
                .ok_or(Error::SigninGone)?;
            Purpose::Authorization(interaction)
        }
        Begin {
            interaction: None,
            account: true,
        } => Purpose::Account,
        Begin { .. } => return Err(Error::Invalid),
    };
    let secret = random_secret().map_err(|_| Error::Internal)?;
    let binding = SigninBinding::from_secret(base64url::encode(&secret));
    let begun = state
        .signins
        .begin(&tenant, &binding, &purpose, now)
        .await
        .map_err(Error::Store)?;
    if !begun {
        // A value just drawn from 256 random bits already in use.
        return Err(Error::Internal);
    }
    Ok(answer(Stage::Identify, Some(binding_cookie(&binding)?)))
}
