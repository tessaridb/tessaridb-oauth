//! A company's mail wording in its console: every kind read with the wording in force, the company's own wording set
//! or reset only from the revision the operator read, by an operator holding `policy`. The trail records the change
//! and its reason, never the wording.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_core::mail_template::{MailKind, Placeholder, Template, TemplateRefused};
use tessari_oauth_storage::mail_templates::{MailTemplateService, Reset, Set, Wording};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::TenantId;

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::operator::signed_in;
use crate::{Error, Result};

/// The read `GET .../api/mail` names when it is refused.
const READ: &str = "mail.read";
/// The change `PUT .../api/mail/{kind}` names.
const SET: &str = "mail.set";
/// The change `POST .../api/mail/{kind}/reset` names.
const RESET: &str = "mail.reset";

/// A company's own wording for one kind: the revision it replaces (0 when it keeps none), the wording, and why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Setting {
    revision: u64,
    subject: String,
    text: String,
    reason: String,
}

/// A reset to the default: the revision of the company's own wording it removes, and why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Resetting {
    revision: u64,
    reason: String,
}

impl Reasoned for Setting {
    fn reason(&self) -> &str {
        &self.reason
    }
}

impl Reasoned for Resetting {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// One kind as the console shows it.
#[derive(Serialize)]
struct Shown<'a> {
    kind: &'static str,
    subject: &'a str,
    text: &'a str,
    own: bool,
    revision: u64,
    placeholders: Vec<&'static str>,
    required: Vec<&'static str>,
}

/// Every kind.
#[derive(Serialize)]
struct Listed<'a> {
    mail: Vec<Shown<'a>>,
}

fn names(placeholders: &[Placeholder]) -> Vec<&'static str> {
    placeholders
        .iter()
        .map(|placeholder| placeholder.name())
        .collect()
}

fn shown(wording: &Wording) -> Shown<'_> {
    Shown {
        kind: wording.kind.name(),
        subject: &wording.template.subject,
        text: &wording.template.text,
        own: wording.own,
        revision: wording.revision,
        placeholders: names(wording.kind.placeholders()),
        required: names(wording.kind.required()),
    }
}

/// The kind the path names, or not found before anything else is looked at.
fn kind_of(name: &str) -> Result<MailKind> {
    MailKind::parse(name).ok_or(Error::NotFound)
}

/// A change's answer: the kind as it now reads.
async fn now_reads(
    templates: &MailTemplateService,
    tenant: &TenantId,
    kind: MailKind,
) -> Result<Made> {
    let wording = templates.wording(tenant).await.map_err(Error::Store)?;
    let current = wording
        .iter()
        .find(|row| row.kind == kind)
        .ok_or(Error::Internal)?;
    made(StatusCode::OK, &shown(current))
}

fn made(status: StatusCode, body: &impl Serialize) -> Result<Made> {
    Ok(Made {
        status,
        body: serde_json::to_string(body).map_err(|_| Error::Internal)?,
        shown: None,
        user: None,
    })
}

/// A refusal kept as the change's answer.
fn refused(status: StatusCode, code: &'static str, message: &'static str) -> Result<Made> {
    made(status, &Refusal { code, message })
}

fn moved() -> Result<Made> {
    refused(
        StatusCode::CONFLICT,
        "changed_meanwhile",
        "the wording changed since it was read; read it again",
    )
}

/// A rule the wording broke, said in the operator's terms.
fn rule_refused(refusal: &TemplateRefused) -> Result<Made> {
    let message = match refusal {
        TemplateRefused::SubjectLength => "the subject must be 1 to 200 characters",
        TemplateRefused::TextLength => "the text must be 1 to 10000 characters",
        TemplateRefused::ControlCharacter => {
            "the subject must be one line, and the text may hold no control character but a line break"
        }
        TemplateRefused::Unbalanced => {
            "a brace opens or closes nothing; write {{ or }} for a brace itself"
        }
        TemplateRefused::Unknown(_) => "a placeholder in braces is not one this server fills",
        TemplateRefused::NotAllowed(_) => "a placeholder in braces is not one this mail carries",
        TemplateRefused::Missing(Placeholder::Link) => "this mail must carry its {link}",
        TemplateRefused::Missing(Placeholder::NewAddress) => {
            "this mail must name the {new_address}"
        }
        TemplateRefused::Missing(Placeholder::Change) => {
            "this mail must say what changed with {change}"
        }
        TemplateRefused::Missing(Placeholder::Issuer) => "this mail must name the {issuer}",
    };
    refused(StatusCode::BAD_REQUEST, "template_rejected", message)
}

/// Every kind with the wording the company sends it with.
pub(super) async fn read(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Policy, READ).await?;
    let wording = state
        .mail_templates
        .wording(&operator.tenant)
        .await
        .map_err(Error::Store)?;
    Ok(Json(Listed {
        mail: wording.iter().map(shown).collect(),
    })
    .into_response())
}

/// Keep the company's own wording for a kind, only from the revision the operator read.
pub(super) async fn set(
    State(state): State<AdminState>,
    Path((company, kind)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let kind = kind_of(&kind)?;
    let templates = Arc::clone(&state.mail_templates);
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Policy, SET),
        |operator, sent: Setting| async move {
            let template = Template {
                subject: sent.subject,
                text: sent.text,
            };
            let set = templates
                .set(
                    &operator.tenant,
                    (kind, sent.revision),
                    &template,
                    &operator.actor.name(),
                    now,
                )
                .await
                .map_err(Error::Store)?;
            match set {
                Set::Made(_) => now_reads(&templates, &operator.tenant, kind).await,
                Set::Moved => moved(),
                Set::Refused(refusal) => rule_refused(&refusal),
            }
        },
    )
    .await
}

/// Send a kind with the default wording again, only from the revision the operator read.
pub(super) async fn reset(
    State(state): State<AdminState>,
    Path((company, kind)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let kind = kind_of(&kind)?;
    let templates = Arc::clone(&state.mail_templates);
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Policy, RESET),
        |operator, sent: Resetting| async move {
            let reset = templates
                .reset(&operator.tenant, kind, sent.revision)
                .await
                .map_err(Error::Store)?;
            match reset {
                Reset::Made => now_reads(&templates, &operator.tenant, kind).await,
                Reset::Moved => moved(),
                Reset::None => refused(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "the company keeps no wording of its own for this mail",
                ),
            }
        },
    )
    .await
}
