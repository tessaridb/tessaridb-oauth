//! A service's admin assertion: how a program the company registered calls its admin API without a console session.
//!
//! The service signs one short-lived JWT per request with the Ed25519 key an operator registered for it. It is
//! verified under that key alone, must carry the admin type (so no client assertion and no token this issuer mints
//! can stand in for it), must name the service as issuer and subject, must be addressed to this company's admin API
//! and nothing else, and may live a minute. The `jti` and expiry are returned for the caller to spend once.

use serde::Deserialize;
use tessari_oauth_constants::{
    CLOCK_SKEW_SECS, JTI_MAX_LEN, SERVICE_ASSERTION_MAX_TTL_SECS, SERVICE_ASSERTION_TYPE,
};
use tessari_oauth_types::{ServiceId, Timestamp};

use crate::jose::{self, Algorithm, VerifyingKey};

/// What a verified assertion leaves to be recorded as spent until it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAssertionUse {
    /// The service that signed it.
    pub service: ServiceId,
    /// Its `jti`.
    pub jti: String,
    /// Its `exp`: the `jti` must be remembered until then.
    pub expires_at: Timestamp,
}

/// The first check an assertion failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceRefusal {
    /// Not a JWS signed with `EdDSA` by the service's registered key.
    Signature,
    /// Not of the admin type.
    Type,
    /// Issuer, subject or `jti` missing or not the service's.
    Claims,
    /// Not addressed to this company's admin API alone.
    Audience,
    /// Expired, or valid for longer than a minute.
    Time,
}

impl ServiceRefusal {
    /// The refusal's name, as the audit trail records it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Signature => "service_signature",
            Self::Type => "service_type",
            Self::Claims => "service_claims",
            Self::Audience => "service_audience",
            Self::Time => "service_time",
        }
    }
}

/// `aud` as a string or an array of strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

/// The claims read here; every other claim is ignored.
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    jti: Option<String>,
}

/// The service `compact` names as its subject, read without verifying anything: used only to find the key it is
/// then verified against.
#[must_use]
pub fn named_service(compact: &str) -> Option<ServiceId> {
    crate::assertion::named_client(compact).and_then(|sub| ServiceId::parse(sub).ok())
}

/// Verify `compact` as `service`'s assertion under `key`, for the admin API at `audience`, at `now`.
///
/// # Errors
///
/// The first check that failed, as a [`ServiceRefusal`].
pub fn verify(
    compact: &str,
    service: &ServiceId,
    key: &VerifyingKey,
    audience: &str,
    now: Timestamp,
) -> Result<ServiceAssertionUse, ServiceRefusal> {
    let verified = jose::verify(compact, Algorithm::EdDsa, std::slice::from_ref(key))
        .map_err(|_| ServiceRefusal::Signature)?;
    if verified.typ.as_deref() != Some(SERVICE_ASSERTION_TYPE) {
        return Err(ServiceRefusal::Type);
    }
    let claims: Claims =
        serde_json::from_slice(&verified.payload).map_err(|_| ServiceRefusal::Claims)?;
    let own = service.as_str();
    if claims.iss != own || claims.sub != own {
        return Err(ServiceRefusal::Claims);
    }
    let sole_audience = match &claims.aud {
        Audience::One(aud) => aud == audience,
        Audience::Many(auds) => matches!(auds.as_slice(), [aud] if aud == audience),
    };
    if !sole_audience {
        return Err(ServiceRefusal::Audience);
    }
    let now = now.unix_secs();
    let expired = claims
        .exp
        .checked_add(CLOCK_SKEW_SECS)
        .is_none_or(|end| now >= end);
    let too_long = now
        .checked_add(SERVICE_ASSERTION_MAX_TTL_SECS)
        .and_then(|bound| bound.checked_add(CLOCK_SKEW_SECS))
        .is_none_or(|bound| claims.exp > bound);
    if expired || too_long {
        return Err(ServiceRefusal::Time);
    }
    let jti = claims
        .jti
        .filter(|jti| !jti.is_empty() && jti.chars().count() <= JTI_MAX_LEN)
        .ok_or(ServiceRefusal::Claims)?;
    Ok(ServiceAssertionUse {
        service: service.clone(),
        jti,
        expires_at: Timestamp::from_unix_secs(claims.exp),
    })
}

#[cfg(test)]
#[path = "service_assertion_tests.rs"]
mod tests;
