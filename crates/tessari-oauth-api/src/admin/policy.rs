//! A company's two-factor and registration policies in its console: read, and changed from the policy the operator saw,
//! by an operator holding `policy`.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_core::registration::{RegistrationPolicy, RegistrationRefused};
use tessari_oauth_core::two_factor::TwoFactorPolicy;
use tessari_oauth_storage::operators::OperatorRole;

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::operator::signed_in;
use crate::{Error, Result};

/// The change `PUT .../api/policy/two-factor` names.
const CHANGE: &str = "policy.two_factor";
/// The read `GET .../api/policy/two-factor` names when it is refused.
const READ: &str = "policy.two_factor.read";

/// A policy change: the policy the operator saw, the one they want, and why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Change {
    expected: String,
    policy: String,
    reason: String,
}

impl Reasoned for Change {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// The policy in force.
#[derive(Serialize)]
struct Policy {
    policy: &'static str,
}

/// The company's two-factor policy.
pub(super) async fn two_factor(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Policy, READ).await?;
    let policy = state
        .policies
        .two_factor(&operator.tenant)
        .await
        .map_err(Error::Store)?;
    Ok(Json(Policy {
        policy: policy.name(),
    })
    .into_response())
}

/// Change the company's two-factor policy, only from the policy the operator saw.
pub(super) async fn set_two_factor(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let policies = std::sync::Arc::clone(&state.policies);
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Policy, CHANGE),
        |operator, sent: Change| async move {
            let expected = TwoFactorPolicy::named(&sent.expected).ok_or(Error::Invalid)?;
            let policy = TwoFactorPolicy::named(&sent.policy).ok_or(Error::Invalid)?;
            let made = policies
                .set_two_factor_if(&operator.tenant, expected, policy)
                .await
                .map_err(Error::Store)?;
            let (status, body) = if made {
                (
                    StatusCode::OK,
                    serde_json::to_string(&Policy {
                        policy: policy.name(),
                    }),
                )
            } else {
                (
                    StatusCode::CONFLICT,
                    serde_json::to_string(&Refusal {
                        code: "changed_meanwhile",
                        message: "the policy changed since it was read; read it again",
                    }),
                )
            };
            Ok(Made {
                status,
                body: body.map_err(|_| Error::Internal)?,
                shown: None,
                user: None,
            })
        },
    )
    .await
}

/// The change `PUT .../api/policy/registration` names.
const REGISTRATION_CHANGE: &str = "policy.registration";
/// The read `GET .../api/policy/registration` names when it is refused.
const REGISTRATION_READ: &str = "policy.registration.read";

/// A registration change: the revision the operator read (0 when none is kept), the policy wanted, and why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistrationChange {
    revision: u64,
    open: bool,
    domains: Vec<String>,
    reason: String,
}

impl Reasoned for RegistrationChange {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// The registration policy in force and the revision a change names.
#[derive(Serialize)]
struct Registration<'a> {
    open: bool,
    domains: &'a [String],
    revision: u64,
}

/// The company's registration policy.
pub(super) async fn registration(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator
        .require(&state, OperatorRole::Policy, REGISTRATION_READ)
        .await?;
    let (policy, revision) = state
        .policies
        .registration(&operator.tenant)
        .await
        .map_err(Error::Store)?;
    Ok(Json(Registration {
        open: policy.is_open(),
        domains: policy.domains(),
        revision,
    })
    .into_response())
}

/// Change the company's registration policy, only from the revision the operator read.
pub(super) async fn set_registration(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let policies = std::sync::Arc::clone(&state.policies);
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Policy, REGISTRATION_CHANGE),
        |operator, sent: RegistrationChange| async move {
            let (status, body) = match RegistrationPolicy::new(sent.open, sent.domains) {
                Err(refused) => (
                    StatusCode::BAD_REQUEST,
                    serde_json::to_string(&Refusal {
                        code: "domains_rejected",
                        message: domains_rule(refused),
                    }),
                ),
                Ok(policy) => {
                    let made = policies
                        .set_registration(&operator.tenant, sent.revision, &policy)
                        .await
                        .map_err(Error::Store)?;
                    match made {
                        Some(revision) => (
                            StatusCode::OK,
                            serde_json::to_string(&Registration {
                                open: policy.is_open(),
                                domains: policy.domains(),
                                revision,
                            }),
                        ),
                        None => (
                            StatusCode::CONFLICT,
                            serde_json::to_string(&Refusal {
                                code: "changed_meanwhile",
                                message: "the policy changed since it was read; read it again",
                            }),
                        ),
                    }
                }
            };
            Ok(Made {
                status,
                body: body.map_err(|_| Error::Internal)?,
                shown: None,
                user: None,
            })
        },
    )
    .await
}

/// The rule a refused domain list broke, said in the operator's terms.
const fn domains_rule(refused: RegistrationRefused) -> &'static str {
    match refused {
        RegistrationRefused::NotADomain => {
            "each domain is a name like example.com: letters, digits and inner hyphens, no wildcard"
        }
        RegistrationRefused::Repeated => "a domain is named twice",
        RegistrationRefused::TooMany => "at most 20 domains",
    }
}
