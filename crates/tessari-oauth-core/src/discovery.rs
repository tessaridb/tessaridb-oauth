//! The authorization-server metadata (RFC 8414), which is also the OpenID Provider metadata (OpenID Connect Discovery
//! 1.0 §3), rendered from the lists the request checks enforce.
//!
//! Nothing here is written by hand: each supported value is read from the constant or enum that the matching check
//! consults, so the document cannot advertise what the server refuses. A field whose check does not exist yet is
//! absent rather than promised.

use serde::Serialize;
use tessari_oauth_constants::{
    AUTHORIZATION_PATH, JWKS_PATH, PAR_PATH, REVOCATION_PATH, TOKEN_PATH, USERINFO_PATH,
};
use tessari_oauth_types::Algorithm;
use url::Url;

use crate::authorize::{CHALLENGE_METHOD_S256, RESPONSE_TYPE_CODE};
use crate::clients::GrantType;
use crate::dpop;
use crate::subject::SUBJECT_TYPE_PAIRWISE;
use crate::token::VERIFIED_AUTH_METHODS;

/// The issuer is not an `https` URL without query, fragment, credentials or trailing slash in its exact
/// serialised form (RFC 8414 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the issuer is not a plain https URL")]
pub struct IssuerRefused;

/// One tenant's metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: String,
    response_types_supported: [&'static str; 1],
    grant_types_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: [&'static str; 2],
    token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    revocation_endpoint: String,
    revocation_endpoint_auth_methods_supported: [&'static str; 2],
    code_challenge_methods_supported: [&'static str; 1],
    dpop_signing_alg_values_supported: Vec<&'static str>,
    authorization_response_iss_parameter_supported: bool,
    pushed_authorization_request_endpoint: String,
    require_pushed_authorization_requests: bool,
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 1],
}

/// The `issuer` exactly as given, when it is a valid issuer identifier.
fn checked(issuer: &str) -> Result<&str, IssuerRefused> {
    let url = Url::parse(issuer).map_err(|_| IssuerRefused)?;
    let plain = url.scheme() == "https"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && !issuer.ends_with('/')
        // The parser's serialisation must be the input, so every token's `iss` can equal it byte for byte.
        && url.as_str() == issuer;
    if plain {
        Ok(issuer)
    } else {
        Err(IssuerRefused)
    }
}

fn algorithm_names(algorithms: &[Algorithm]) -> Vec<&'static str> {
    algorithms
        .iter()
        .map(|algorithm| algorithm.name())
        .collect()
}

/// The metadata of the tenant whose issuer is `issuer` and whose ID tokens are signed with `id_token_algorithm`.
///
/// # Errors
///
/// [`IssuerRefused`] when `issuer` is not a valid issuer identifier.
pub fn metadata(issuer: &str, id_token_algorithm: Algorithm) -> Result<Metadata, IssuerRefused> {
    let issuer = checked(issuer)?;
    Ok(Metadata {
        issuer: issuer.to_owned(),
        authorization_endpoint: format!("{issuer}{AUTHORIZATION_PATH}"),
        token_endpoint: format!("{issuer}{TOKEN_PATH}"),
        jwks_uri: format!("{issuer}{JWKS_PATH}"),
        userinfo_endpoint: format!("{issuer}{USERINFO_PATH}"),
        response_types_supported: [RESPONSE_TYPE_CODE],
        grant_types_supported: GrantType::ALL.iter().map(|grant| grant.name()).collect(),
        token_endpoint_auth_methods_supported: VERIFIED_AUTH_METHODS,
        token_endpoint_auth_signing_alg_values_supported: algorithm_names(&Algorithm::ALL),
        // The revocation endpoint authenticates a client exactly as the token endpoint does.
        revocation_endpoint: format!("{issuer}{REVOCATION_PATH}"),
        revocation_endpoint_auth_methods_supported: VERIFIED_AUTH_METHODS,
        code_challenge_methods_supported: [CHALLENGE_METHOD_S256],
        dpop_signing_alg_values_supported: algorithm_names(&dpop::ALGORITHMS),
        // Every authorization response carries `iss` (RFC 9207).
        authorization_response_iss_parameter_supported: true,
        // A client may push its request (RFC 9126); none is made to, so the browser's URL still works.
        pushed_authorization_request_endpoint: format!("{issuer}{PAR_PATH}"),
        require_pushed_authorization_requests: false,
        // Every client knows a user by a pairwise identifier (OpenID Connect Core §8.1).
        subject_types_supported: [SUBJECT_TYPE_PAIRWISE],
        id_token_signing_alg_values_supported: [id_token_algorithm.name()],
    })
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
