//! A company's signing keys in its console, by an operator holding `keys`: each key's state as the rotation rule
//! decides it, a successor made early, and a compromised key withdrawn at once. The rule keeps its order, so a new
//! key signs only once verifiers can have fetched it, and a withdrawal never leaves the company without a key to sign
//! with: when no other usable key would remain, the replacement is made before the withdrawal. No private half is ever
//! read here, and keys are generated and sealed inside custody exactly as the rotation daemon makes them.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::JWKS_MAX_AGE_SECS;
use tessari_oauth_core::keys::{self, KeyPlan, KeyRecord};
use tessari_oauth_storage::keys::StoredKey;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{KeyThumbprint, Timestamp};

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::operator::signed_in;
use crate::{Error, Result};

/// The read `GET .../api/keys` names when it is refused.
const READ: &str = "keys.read";
/// The change `POST .../api/keys/rotate` names.
const ROTATE: &str = "keys.rotate";
/// The change `POST .../api/keys/<kid>/withdraw` names.
const WITHDRAW: &str = "keys.withdraw";

/// A change to the keys: why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reason {
    reason: String,
}

impl Reasoned for Reason {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// One key as the console shows it.
#[derive(Serialize)]
struct Shown<'a> {
    kid: &'a str,
    algorithm: &'static str,
    /// Unix seconds of when it was made, which is when it was published.
    created_at: u64,
    /// `signing`, `waiting` (published, signs from `signs_from`), `previous` (published for tokens it signed),
    /// `retiring` (no longer published) or `withdrawn`.
    state: &'static str,
    signs_from: Option<u64>,
}

/// The company's keys, oldest first.
#[derive(Serialize)]
struct Listed<'a> {
    keys: Vec<Shown<'a>>,
}

/// A successor made: its `kid` and when it signs.
#[derive(Serialize)]
struct Rotated<'a> {
    kid: &'a str,
    signs_from: u64,
}

/// A key withdrawn, and the key made to replace it when none other could sign.
#[derive(Serialize)]
struct Withdrawn<'a> {
    withdrawn: &'a str,
    replacement: Option<&'a str>,
}

/// The rule's decision over `live` at `now`.
fn plan_of(live: &[StoredKey], now: Timestamp) -> KeyPlan {
    let records: Vec<KeyRecord> = live
        .iter()
        .map(|key| KeyRecord {
            kid: key.kid.clone(),
            created_at: key.created_at,
            compromised: key.compromised,
        })
        .collect();
    keys::plan(&records, now)
}

/// When `key` may sign: once it has been published for the key set's cache lifetime.
fn signs_from(key: &StoredKey) -> Result<u64> {
    key.created_at
        .unix_secs()
        .checked_add(JWKS_MAX_AGE_SECS)
        .ok_or(Error::Internal)
}

fn shown<'a>(key: &'a StoredKey, plan: &KeyPlan) -> Result<Shown<'a>> {
    let state = if key.compromised {
        "withdrawn"
    } else if plan.signing.as_ref() == Some(&key.kid) {
        "signing"
    } else if !plan.published.contains(&key.kid) {
        "retiring"
    } else if is_after_signer(key, plan) {
        "waiting"
    } else {
        "previous"
    };
    Ok(Shown {
        kid: key.kid.as_str(),
        algorithm: key.algorithm.name(),
        created_at: key.created_at.unix_secs(),
        state,
        signs_from: (state == "waiting").then(|| signs_from(key)).transpose()?,
    })
}

/// Whether `key` was published after the key the plan signs with.
fn is_after_signer(key: &StoredKey, plan: &KeyPlan) -> bool {
    let Some(signer) = plan.signing.as_ref() else {
        return false;
    };
    let position =
        |kid: &KeyThumbprint| plan.published.iter().position(|published| published == kid);
    matches!((position(&key.kid), position(signer)), (Some(at), Some(signing)) if at > signing)
}

/// A refusal kept as the change's answer.
fn refused(status: StatusCode, code: &'static str, message: &'static str) -> Result<Made> {
    Ok(Made {
        status,
        body: serde_json::to_string(&Refusal { code, message }).map_err(|_| Error::Internal)?,
        shown: None,
        user: None,
    })
}

fn answered(body: &impl Serialize) -> Result<Made> {
    Ok(Made {
        status: StatusCode::OK,
        body: serde_json::to_string(body).map_err(|_| Error::Internal)?,
        shown: None,
        user: None,
    })
}

/// The company's keys with their states, oldest first.
pub(super) async fn read(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Keys, READ).await?;
    let live = state
        .keys
        .live(&operator.tenant)
        .await
        .map_err(Error::Store)?;
    let plan = plan_of(&live, (state.clock)());
    let keys = live
        .iter()
        .map(|key| shown(key, &plan))
        .collect::<Result<Vec<_>>>()?;
    Ok(Json(Listed { keys }).into_response())
}

/// Make a successor now, while none waits; it signs once verifiers can have fetched it.
pub(super) async fn rotate(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let (keys, kek, algorithm) = (
        std::sync::Arc::clone(&state.keys),
        std::sync::Arc::clone(&state.kek),
        state.signing_algorithm,
    );
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Keys, ROTATE),
        |operator, _: Reason| async move {
            let live = keys.live(&operator.tenant).await.map_err(Error::Store)?;
            let plan = plan_of(&live, now);
            let waiting = live
                .iter()
                .any(|key| !key.compromised && is_after_signer(key, &plan));
            if waiting {
                return refused(
                    StatusCode::CONFLICT,
                    "successor_waiting",
                    "a successor is already published and waiting to sign",
                );
            }
            let kid = keys
                .generate(&operator.tenant, &kek, algorithm, now)
                .await
                .map_err(Error::Store)?;
            let signs_from = now
                .unix_secs()
                .checked_add(JWKS_MAX_AGE_SECS)
                .ok_or(Error::Internal)?;
            answered(&Rotated {
                kid: kid.as_str(),
                signs_from,
            })
        },
    )
    .await
}

/// Withdraw `kid` at once, making its replacement first when no other key could sign.
pub(super) async fn withdraw(
    State(state): State<AdminState>,
    Path((company, kid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let (keys, kek, algorithm) = (
        std::sync::Arc::clone(&state.keys),
        std::sync::Arc::clone(&state.kek),
        state.signing_algorithm,
    );
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Keys, WITHDRAW),
        |operator, _: Reason| async move {
            let tenant = &operator.tenant;
            let live = keys.live(tenant).await.map_err(Error::Store)?;
            let Some(key) = KeyThumbprint::parse(kid)
                .ok()
                .and_then(|kid| live.iter().find(|key| key.kid == kid))
            else {
                return refused(
                    StatusCode::NOT_FOUND,
                    "key_not_found",
                    "this company has no such key",
                );
            };
            if key.compromised {
                return refused(
                    StatusCode::CONFLICT,
                    "already_withdrawn",
                    "this key is already withdrawn",
                );
            }
            let usable = |keys: &[StoredKey], except: &KeyThumbprint| {
                keys.iter()
                    .any(|other| !other.compromised && &other.kid != except)
            };
            let mut replacement = None;
            if !usable(&live, &key.kid) {
                replacement = Some(
                    keys.generate(tenant, &kek, algorithm, now)
                        .await
                        .map_err(Error::Store)?,
                );
            }
            keys.compromise(tenant, &key.kid)
                .await
                .map_err(Error::Store)?;
            // Two withdrawals racing over the last two keys could each have seen the other's key as usable.
            let after = keys.live(tenant).await.map_err(Error::Store)?;
            if replacement.is_none() && !usable(&after, &key.kid) {
                replacement = Some(
                    keys.generate(tenant, &kek, algorithm, now)
                        .await
                        .map_err(Error::Store)?,
                );
            }
            answered(&Withdrawn {
                withdrawn: key.kid.as_str(),
                replacement: replacement.as_ref().map(KeyThumbprint::as_str),
            })
        },
    )
    .await
}
