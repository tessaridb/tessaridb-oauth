//! The console session after sign-in: `GET /admin/{company}/api/me` answers for its operator only while the issuer
//! session it came from is alive and the operator still holds a current grant, and ends it otherwise;
//! `POST /admin/{company}/signout` ends it for a request from the console's own origin.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::operator::{company_of, from_console, held, signed_in};
use super::{AdminState, SESSION_COOKIE};
use crate::{Error, Result};

/// Who the console is signed in as.
#[derive(Serialize)]
struct Me {
    /// The operator's user id.
    user: String,
    /// The roles they hold now.
    roles: Vec<&'static str>,
}

/// The operator of this browser's console session, and the roles they hold now.
pub(super) async fn me(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    let user = operator.in_console(&state, "me").await?;
    Ok(Json(Me {
        user: user.as_str().to_owned(),
        roles: operator.roles.iter().map(|role| role.name()).collect(),
    })
    .into_response())
}

/// End this browser's console session, when the request comes from the console itself.
pub(super) async fn signout(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let tenant = company_of(&state, &company)?;
    from_console(&state, &headers)?;
    if let Some(secret) = held(&state, &headers) {
        state
            .admin
            .end(&tenant, &secret)
            .await
            .map_err(Error::Store)?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        state.cookie(SESSION_COOKIE, "", "Strict", 0)?,
    );
    Ok(response)
}
