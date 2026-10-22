//! The company directory in the `system` console, for an operator holding `companies` (a role only `system` users can
//! hold): companies listed, and created, provisioned and served at once. A creation that stopped before its company
//! was served is completed by sending it again.

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::COMPANY_PAGE_MAX;
use tessari_oauth_storage::companies::{Company, CompanyStatus, Created};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::provision;
use tessari_oauth_types::TenantId;

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::operator::signed_in;
use crate::{Error, Result};

/// The read the list names when it is refused.
const READ: &str = "companies.read";
/// The change `POST .../api/companies` names.
const CREATE: &str = "companies.create";

/// A page asked for: after a company, and how many.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Listing {
    after: Option<String>,
    limit: Option<u32>,
}

/// A company to create: its id, the name people see, and why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Creating {
    id: String,
    name: String,
    reason: String,
}

impl Reasoned for Creating {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// One company as the console shows it.
#[derive(Serialize)]
struct Shown {
    id: String,
    name: String,
    status: &'static str,
    created_at: u64,
    created_by: String,
}

/// A page of companies, and the cursor of the next one when this one is full.
#[derive(Serialize)]
struct Page {
    companies: Vec<Shown>,
    next: Option<String>,
}

/// The companies of the directory, after `after`.
pub(super) async fn list(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    listing: std::result::Result<Query<Listing>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator
        .require(&state, OperatorRole::Companies, READ)
        .await?;
    let Query(listing) = listing.map_err(|_| Error::Invalid)?;
    let limit = listing.limit.unwrap_or(COMPANY_PAGE_MAX);
    if !(1..=COMPANY_PAGE_MAX).contains(&limit) {
        return Err(Error::Invalid);
    }
    let after = listing
        .after
        .map(|after| TenantId::parse(after).map_err(|_| Error::Invalid))
        .transpose()?;
    let companies = state
        .companies
        .page(after.as_ref(), limit)
        .await
        .map_err(Error::Store)?;
    let full = u32::try_from(companies.len()).is_ok_and(|count| count == limit);
    let next = companies
        .last()
        .filter(|_| full)
        .map(|company| company.id.as_str().to_owned());
    let companies = companies.into_iter().map(shown).collect();
    Ok(Json(Page { companies, next }).into_response())
}

/// Create the company the request names, provision it and serve it.
pub(super) async fn create(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let creating = state.clone();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Companies, CREATE),
        |operator, sent: Creating| async move {
            let id = TenantId::parse(sent.id.as_str()).map_err(|_| Error::Invalid)?;
            let now = (creating.clock)();
            let made = creating
                .companies
                .create(&id, &sent.name, operator.user.as_str(), now)
                .await
                .map_err(|failure| match failure {
                    tessari_oauth_storage::Error::Invalid { .. } => Error::Invalid,
                    failure => Error::Store(failure),
                })?;
            if made == Created::Taken {
                let found = creating.companies.find(&id).await.map_err(Error::Store)?;
                if found.is_none_or(|company| company.status != CompanyStatus::Provisioning) {
                    return Ok(Made {
                        status: StatusCode::CONFLICT,
                        body: serde_json::to_string(&Refusal {
                            code: "company_taken",
                            message: "a company with this id exists already",
                        })
                        .map_err(|_| Error::Internal)?,
                        shown: None,
                        user: None,
                    });
                }
            }
            provision(
                &creating.tenants,
                &creating.clients,
                &id,
                (&creating.public, &creating.console),
                now,
            )
            .await
            .map_err(Error::Store)?;
            creating
                .companies
                .transition(&id, CompanyStatus::Provisioning, CompanyStatus::Active)
                .await
                .map_err(Error::Store)?;
            creating
                .served
                .replace(creating.companies.active().await.map_err(Error::Store)?);
            let company = creating
                .companies
                .find(&id)
                .await
                .map_err(Error::Store)?
                .ok_or(Error::Internal)?;
            Ok(Made {
                status: StatusCode::CREATED,
                body: serde_json::to_string(&shown(company)).map_err(|_| Error::Internal)?,
                shown: None,
                user: None,
            })
        },
    )
    .await
}

/// `company` as the console shows it.
fn shown(company: Company) -> Shown {
    Shown {
        id: company.id.as_str().to_owned(),
        name: company.name,
        status: company.status.name(),
        created_at: company.created_at.unix_secs(),
        created_by: company.created_by,
    }
}
