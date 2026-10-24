//! Services registered in a company's console: programs that call its admin API without a console session, each
//! with the one Ed25519 public key its assertions verify under and the `users` role. Only an operator in the console
//! holding `users` registers, lists or removes one, so a service can never mint another; registering is a named change
//! with a reason, made once per `Idempotency-Key`, and a removed service's next assertion is refused.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::service_credentials::{NewService, ServiceCredential};
use tessari_oauth_types::{ErrorCategory, ServiceId};

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::operator::signed_in;
use crate::{Error, Result};

/// The change and the read the routes below name.
const REGISTER: &str = "services.register";
const REMOVE: &str = "services.remove";
const READ: &str = "services.read";

/// The change `POST .../api/services` names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registering {
    service_id: String,
    jwk: Box<RawValue>,
    roles: Vec<String>,
    reason: String,
}

impl Reasoned for Registering {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// The change `POST .../api/services/<id>/remove` names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Removal {
    reason: String,
}

impl Reasoned for Removal {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// One service as the console shows it.
#[derive(Serialize)]
struct Shown {
    service_id: String,
    roles: Vec<&'static str>,
    registered_by: String,
    registered_at: u64,
}

/// A removal's answer.
#[derive(Serialize)]
struct Removed<'a> {
    service_id: &'a str,
}

/// Every service the company registered.
#[derive(Serialize)]
struct Listed {
    services: Vec<Shown>,
}

fn shown(service: &ServiceCredential) -> Shown {
    Shown {
        service_id: service.id.as_str().to_owned(),
        roles: service.roles.iter().map(|role| role.name()).collect(),
        registered_by: service.registered_by.clone(),
        registered_at: service.registered_at.unix_secs(),
    }
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

/// The company's services.
pub(super) async fn list(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Users, READ).await?;
    operator.in_console(&state, READ).await?;
    let services = state
        .services
        .list(&operator.tenant)
        .await
        .map_err(Error::Store)?;
    Ok(Json(Listed {
        services: services.iter().map(shown).collect(),
    })
    .into_response())
}

/// Register the service the request describes in `company`.
pub(super) async fn register(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let registering = state.clone();
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, REGISTER),
        |operator, sent: Registering| async move {
            let by = operator.in_console(&registering, REGISTER).await?.clone();
            let id = ServiceId::parse(sent.service_id).map_err(|_| Error::Invalid)?;
            let roles = sent
                .roles
                .iter()
                .map(|name| OperatorRole::parse(name).ok_or(Error::Invalid))
                .collect::<Result<Vec<_>>>()?;
            let service = NewService {
                id,
                public_jwk: sent.jwk.get().to_owned(),
                roles,
                registered_by: by.as_str().to_owned(),
                reason: sent.reason,
            };
            match registering
                .services
                .register(&operator.tenant, &service, now)
                .await
            {
                Ok(made) => Ok(Made {
                    status: StatusCode::CREATED,
                    body: serde_json::to_string(&shown(&made)).map_err(|_| Error::Internal)?,
                    shown: None,
                    user: None,
                }),
                Err(failure) if failure.category() == ErrorCategory::Conflict => refused(
                    StatusCode::CONFLICT,
                    "service_taken",
                    "this company already has a service by that id",
                ),
                Err(failure) if failure.category() == ErrorCategory::Validation => {
                    Err(Error::Invalid)
                }
                Err(failure) => Err(Error::Store(failure)),
            }
        },
    )
    .await
}

/// Remove the company's service `service`; its next assertion is refused.
pub(super) async fn remove(
    State(state): State<AdminState>,
    Path((company, service)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let removing = state.clone();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, REMOVE),
        |operator, _: Removal| async move {
            operator.in_console(&removing, REMOVE).await?;
            let removed = match ServiceId::parse(service) {
                Ok(id) => removing
                    .services
                    .remove(&operator.tenant, &id)
                    .await
                    .map_err(Error::Store)?
                    .then_some(id),
                Err(_) => None,
            };
            let Some(id) = removed else {
                return refused(
                    StatusCode::NOT_FOUND,
                    "service_not_found",
                    "this company has no such service",
                );
            };
            Ok(Made {
                status: StatusCode::OK,
                body: serde_json::to_string(&Removed {
                    service_id: id.as_str(),
                })
                .map_err(|_| Error::Internal)?,
                shown: None,
                user: None,
            })
        },
    )
    .await
}
