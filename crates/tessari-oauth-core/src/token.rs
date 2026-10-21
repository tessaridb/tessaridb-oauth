//! `/token` validation, in the fixed order.
//!
//! The client is authenticated BEFORE the grant is read: a server that decodes a code to learn which client it
//! belongs to lets the code authenticate its presenter. Then the grant type, which the client must have registered,
//! then — after the storage layer has atomically consumed the code — every binding the code was issued with, each
//! refused on its own. The refresh grant's own checks are in [`crate::refresh`].

use tessari_oauth_types::{ClientId, ErrorCode, ScopeSet, TenantId, Timestamp};

use crate::assertion::{self, AssertionUse};
use crate::clients::{AuthMethod, ClientDirectory, ClientRegistration, GrantType};
use crate::codes::IssuedCode;
use crate::{Params, Reason};

/// The `grant_type` of the authorization-code grant.
const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";

/// The `grant_type` of the refresh grant.
const GRANT_REFRESH_TOKEN: &str = "refresh_token";

/// A token-endpoint refusal: the `error` value for the caller and the reason for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// The `error` value of the response.
    pub error: ErrorCode,
    /// The check that refused, for the audit log.
    pub reason: Reason,
}

/// What a request presented as client authentication, as the HTTP layer observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedAuth {
    /// `client_id` in the body and no credential.
    None,
    /// HTTP Basic credentials.
    ClientSecretBasic,
    /// `client_secret` in the body.
    ClientSecretPost,
    /// `client_assertion` in the body.
    PrivateKeyJwt,
}

/// The token endpoint a request arrived at: its tenant, that tenant's issuer, and the time it is judged at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The tenant the endpoint serves.
    pub tenant: TenantId,
    /// The tenant's issuer identifier, the only audience a client assertion may name.
    pub issuer: String,
    /// The request's time.
    pub now: Timestamp,
}

/// An authenticated client, and the assertion it spent when it authenticated with one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// The client's registration.
    pub client: ClientRegistration,
    /// The assertion to record as spent; `None` for a public client.
    pub assertion: Option<AssertionUse>,
}

/// The `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2).
const JWT_BEARER_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A redeemed code's grant, ready to be minted into tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redemption {
    /// The client the tokens are issued to.
    pub client_id: ClientId,
    /// The scopes the code granted.
    pub scopes: ScopeSet,
}

/// Read a token request's parameters, refusing a repeated one.
///
/// # Errors
///
/// `invalid_request` with [`Reason::DuplicateParameter`].
pub fn read<I, K, V>(pairs: I) -> Result<Params, Refusal>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    Params::from_pairs(pairs)
        .map_err(|_| refuse(ErrorCode::InvalidRequest, Reason::DuplicateParameter))
}

/// A refusal with `error` for the caller and `reason` for the audit log.
const fn refuse(error: ErrorCode, reason: Reason) -> Refusal {
    Refusal { error, reason }
}

/// Authenticate the client of `params` at `endpoint` by the method pinned at its registration.
///
/// # Errors
///
/// `invalid_client` for an absent, malformed or unknown `client_id`, a method other than the pinned one, or an
/// assertion that does not hold (see [`crate::assertion::verify`]).
pub fn authenticate_client(
    endpoint: &Endpoint,
    directory: &impl ClientDirectory,
    presented: PresentedAuth,
    params: &Params,
) -> Result<Authenticated, Refusal> {
    let tenant = &endpoint.tenant;
    let raw = params
        .get("client_id")
        .ok_or(refuse(ErrorCode::InvalidClient, Reason::MissingParameter))?;
    let client_id = ClientId::parse(raw)
        .map_err(|_| refuse(ErrorCode::InvalidClient, Reason::MalformedParameter))?;
    let client = directory
        .find(tenant, &client_id)
        .filter(|registration| registration.tenant == *tenant)
        .ok_or(refuse(ErrorCode::InvalidClient, Reason::UnknownClient))?;
    let assertion = match (client.auth_method, presented) {
        (AuthMethod::None, PresentedAuth::None) => None,
        (AuthMethod::PrivateKeyJwt(_), PresentedAuth::PrivateKeyJwt) => {
            Some(presented_assertion(endpoint, &client, params)?)
        }
        // Secret methods are pinnable but not verifiable yet, so a client pinned to one is refused, not trusted.
        _ => {
            return Err(refuse(
                ErrorCode::InvalidClient,
                Reason::AuthMethodNotPinned,
            ));
        }
    };
    Ok(Authenticated { client, assertion })
}

/// The JWT assertion `params` carries, verified as `client`'s.
fn presented_assertion(
    endpoint: &Endpoint,
    client: &ClientRegistration,
    params: &Params,
) -> Result<AssertionUse, Refusal> {
    let missing = refuse(ErrorCode::InvalidClient, Reason::MissingParameter);
    match params.get("client_assertion_type") {
        None => return Err(missing),
        Some(JWT_BEARER_ASSERTION) => {}
        Some(_) => {
            return Err(refuse(ErrorCode::InvalidClient, Reason::MalformedParameter));
        }
    }
    let assertion = params.get("client_assertion").ok_or(missing)?;
    assertion::verify(assertion, client, &endpoint.issuer, endpoint.now)
}

/// The grant `params` asks for, when this endpoint redeems it and `client` registered it.
///
/// # Errors
///
/// `invalid_request` when absent; `unsupported_grant_type` for a grant this endpoint does not redeem;
/// `unauthorized_client` for one the client did not register.
pub fn require_grant(params: &Params, client: &ClientRegistration) -> Result<GrantType, Refusal> {
    let grant = match params.get("grant_type") {
        None => return Err(refuse(ErrorCode::InvalidRequest, Reason::MissingParameter)),
        Some(GRANT_AUTHORIZATION_CODE) => GrantType::AuthorizationCode,
        Some(GRANT_REFRESH_TOKEN) => GrantType::RefreshToken,
        Some(_) => {
            return Err(refuse(
                ErrorCode::UnsupportedGrantType,
                Reason::UnsupportedGrantType,
            ));
        }
    };
    if !client.grant_types.contains(&grant) {
        return Err(refuse(
            ErrorCode::UnauthorizedClient,
            Reason::GrantNotRegistered,
        ));
    }
    Ok(grant)
}

/// Check every binding of a consumed code against the authenticated client and the request.
///
/// # Errors
///
/// `invalid_grant` naming the first binding that does not hold.
pub fn redeem_code(
    tenant: &TenantId,
    client: &ClientRegistration,
    params: &Params,
    code: &IssuedCode,
    now: Timestamp,
) -> Result<Redemption, Refusal> {
    let invalid_grant = |reason| refuse(ErrorCode::InvalidGrant, reason);
    if code.tenant != *tenant {
        return Err(invalid_grant(Reason::CodeTenantMismatch));
    }
    if code.client_id != client.client_id {
        return Err(invalid_grant(Reason::CodeClientMismatch));
    }
    if now >= code.expires_at {
        return Err(invalid_grant(Reason::CodeExpired));
    }
    if params.get("redirect_uri") != Some(code.redirect_uri.as_str()) {
        return Err(invalid_grant(Reason::CodeRedirectMismatch));
    }
    let verifier = params
        .get("code_verifier")
        .ok_or(invalid_grant(Reason::VerifierMissing))?;
    if !code.challenge.matches(verifier) {
        return Err(invalid_grant(Reason::VerifierMismatch));
    }
    Ok(Redemption {
        client_id: code.client_id.clone(),
        scopes: code.scopes.clone(),
    })
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;
