//! The signed-in user's own profile: three names set and replaced whole, each trimmed and at most 100 characters with
//! no control character; a name that is not sent, or is empty, is cleared. UserInfo releases them under `profile`.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_storage::users::Profile;

use super::login::{body, signed_in};
use crate::state::PublicState;
use crate::{Error, Result};

/// The names as sent; any of them may be left out.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Names {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
}

/// The names as kept, each `null` until set.
#[derive(Serialize)]
pub(super) struct View {
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

impl From<Profile> for View {
    fn from(profile: Profile) -> Self {
        Self {
            name: profile.name,
            given_name: profile.given_name,
            family_name: profile.family_name,
        }
    }
}

#[derive(Serialize)]
struct Answer {
    profile: View,
}

pub(super) async fn set(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Names>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let names = body(read)?;
    let now = (state.clock)();
    let user = signed_in(&state, &tenant, &headers, now).await?.user;
    let wanted = Profile {
        name: names.name,
        given_name: names.given_name,
        family_name: names.family_name,
    };
    let set = state
        .users
        .set_profile(&tenant, &user, &wanted)
        .await
        .map_err(|failure| match failure {
            tessari_oauth_storage::Error::Invalid {
                record: "profile", ..
            } => Error::ProfileRejected,
            other => Error::Store(other),
        })?;
    // A session names an account that existed when it signed in, and accounts are never removed.
    if !set {
        return Err(Error::Internal);
    }
    let kept = state
        .users
        .profile(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Internal)?;
    let answer = Answer {
        profile: kept.into(),
    };
    Ok((StatusCode::OK, Json(answer)).into_response())
}
