//! A company's brand in its console, by an operator holding `policy`: read with the revision a change must name,
//! replaced whole only from that revision, and its logo replaced or removed. Every value is read by the type the
//! server keeps it as, and a logo is kept only as the server's own re-encoding of the PNG it was sent.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_core::branding::{Accent, BrandLink, BrandName, BrandRefusal};
use tessari_oauth_core::logo::reencode;
use tessari_oauth_storage::brands::{Brand, Revised};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{Timestamp, base64url};

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::operator::signed_in;
use crate::{Error, Result};

/// The read `GET .../api/branding` names when it is refused.
const READ: &str = "branding.read";
/// The change `PUT .../api/branding` names.
const SET: &str = "branding.set";
/// The change `PUT .../api/branding/logo` names.
const SET_LOGO: &str = "branding.logo";
/// The change `POST .../api/branding/logo/remove` names.
const REMOVE_LOGO: &str = "branding.logo.remove";

/// A brand to set: the revision it replaces (0 when none is set), its values, and why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Setting {
    revision: u64,
    name: String,
    accent: String,
    support_url: Option<String>,
    privacy_url: Option<String>,
    reason: String,
}

/// A logo to set: the PNG as base64url, and why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Uploading {
    png: String,
    reason: String,
}

/// A logo removal: why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Removal {
    reason: String,
}

impl Reasoned for Setting {
    fn reason(&self) -> &str {
        &self.reason
    }
}

impl Reasoned for Uploading {
    fn reason(&self) -> &str {
        &self.reason
    }
}

impl Reasoned for Removal {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// The brand as the console shows it; every value null and the revision 0 when none is set.
#[derive(Serialize)]
struct Shown<'a> {
    name: Option<&'a str>,
    accent: Option<&'a str>,
    support_url: Option<&'a str>,
    privacy_url: Option<&'a str>,
    /// Unix seconds of the logo's upload.
    logo: Option<u64>,
    revision: u64,
}

/// A logo set, by its upload time; or removed.
#[derive(Serialize)]
struct Logo {
    logo: Option<u64>,
}

fn shown(revised: Option<&Revised>, logo: Option<Timestamp>) -> Shown<'_> {
    let brand = revised.map(|revised| &revised.brand);
    Shown {
        name: brand.map(|brand| brand.name.as_str()),
        accent: brand.map(|brand| brand.accent.as_str()),
        support_url: brand
            .and_then(|brand| brand.support.as_ref())
            .map(BrandLink::as_str),
        privacy_url: brand
            .and_then(|brand| brand.privacy.as_ref())
            .map(BrandLink::as_str),
        logo: logo.map(Timestamp::unix_secs),
        revision: revised.map_or(0, |revised| revised.revision),
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

/// A value the brand rules refused, said in the operator's terms.
fn rule_refused(refusal: BrandRefusal) -> Result<Made> {
    let message = match refusal {
        BrandRefusal::NameInvalid => {
            "the name must be 1 to 64 characters with no control or direction characters"
        }
        BrandRefusal::AccentInvalid => "the colour must be # and six hex digits",
        BrandRefusal::AccentLowContrast => {
            "white text cannot be read on this colour; choose a darker one"
        }
        BrandRefusal::LinkInvalid => {
            "a link must be an https address with a host and no credentials"
        }
        BrandRefusal::LogoTooLarge => "the logo is larger than 256 KiB",
        BrandRefusal::LogoNotPng => "the logo must be a PNG image",
        BrandRefusal::LogoUnreadable => "the logo could not be read as a PNG image",
        BrandRefusal::LogoTooWide => "the logo must be at most 512 by 512 pixels",
    };
    refused(StatusCode::BAD_REQUEST, refusal.code(), message)
}

/// `sent` as a brand set `at`, or the rule it broke.
fn brand_of(sent: &Setting, at: Timestamp) -> std::result::Result<Brand, BrandRefusal> {
    let link = |raw: &Option<String>| raw.as_deref().map(BrandLink::parse).transpose();
    Ok(Brand {
        name: BrandName::parse(&sent.name)?,
        accent: Accent::parse(&sent.accent)?,
        support: link(&sent.support_url)?,
        privacy: link(&sent.privacy_url)?,
        updated_at: at,
    })
}

/// The company's brand, with the revision a change must name.
pub(super) async fn read(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Policy, READ).await?;
    let revised = state
        .brands
        .find(&operator.tenant)
        .await
        .map_err(Error::Store)?;
    let logo = state
        .brands
        .logo_updated(&operator.tenant)
        .await
        .map_err(Error::Store)?;
    Ok(Json(shown(revised.as_ref(), logo)).into_response())
}

/// Set the company's brand whole, only over the revision the operator read.
pub(super) async fn set(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let brands = std::sync::Arc::clone(&state.brands);
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Policy, SET),
        |operator, sent: Setting| async move {
            let brand = match brand_of(&sent, now) {
                Ok(brand) => brand,
                Err(refusal) => return rule_refused(refusal),
            };
            let made = brands
                .set(&operator.tenant, sent.revision, &brand)
                .await
                .map_err(Error::Store)?;
            if !made {
                return refused(
                    StatusCode::CONFLICT,
                    "changed_meanwhile",
                    "the brand changed since it was read; read it again",
                );
            }
            let revised = brands.find(&operator.tenant).await.map_err(Error::Store)?;
            let logo = brands
                .logo_updated(&operator.tenant)
                .await
                .map_err(Error::Store)?;
            Ok(Made {
                status: StatusCode::OK,
                body: serde_json::to_string(&shown(revised.as_ref(), logo))
                    .map_err(|_| Error::Internal)?,
                shown: None,
                user: None,
            })
        },
    )
    .await
}

/// Set the company's logo to the server's re-encoding of the PNG sent.
pub(super) async fn set_logo(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let brands = std::sync::Arc::clone(&state.brands);
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Policy, SET_LOGO),
        |operator, sent: Uploading| async move {
            let upload = base64url::decode(&sent.png).map_err(|_| Error::Invalid)?;
            // Decoding is CPU work proportional to the image, kept off the runtime's workers.
            let png = match tokio::task::spawn_blocking(move || reencode(&upload))
                .await
                .map_err(|_| Error::Internal)?
            {
                Ok(png) => png,
                Err(refusal) => return rule_refused(refusal),
            };
            brands
                .set_logo(&operator.tenant, &png, now)
                .await
                .map_err(Error::Store)?;
            Ok(Made {
                status: StatusCode::OK,
                body: serde_json::to_string(&Logo {
                    logo: Some(now.unix_secs()),
                })
                .map_err(|_| Error::Internal)?,
                shown: None,
                user: None,
            })
        },
    )
    .await
}

/// Remove the company's logo, so its pages show the product mark again.
pub(super) async fn remove_logo(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let brands = std::sync::Arc::clone(&state.brands);
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Policy, REMOVE_LOGO),
        |operator, _: Removal| async move {
            if !brands
                .remove_logo(&operator.tenant)
                .await
                .map_err(Error::Store)?
            {
                return refused(StatusCode::NOT_FOUND, "no_logo", "this company has no logo");
            }
            Ok(Made {
                status: StatusCode::OK,
                body: serde_json::to_string(&Logo { logo: None }).map_err(|_| Error::Internal)?,
                shown: None,
                user: None,
            })
        },
    )
    .await
}
