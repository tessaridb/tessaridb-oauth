//! `/token` validation, in the fixed order.
//!
//! The client is authenticated BEFORE the grant is read: a server that decodes a code to learn which client it
//! belongs to lets the code authenticate its presenter. Then the grant type, which the client must have registered,
//! then — after the storage layer has atomically consumed the code — every binding the code was issued with, each
//! refused on its own. The refresh grant's own checks are in [`crate::refresh`].

use tessari_oauth_types::{ClientId, ErrorCode, ScopeSet, TenantId, Timestamp};

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
}

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

/// Authenticate the client of `params` in `tenant` by the method pinned at its registration.
///
/// # Errors
///
/// `invalid_client` for an absent, malformed or unknown `client_id`, or a method other than the pinned one.
pub fn authenticate_client(
    tenant: &TenantId,
    directory: &impl ClientDirectory,
    presented: PresentedAuth,
    params: &Params,
) -> Result<ClientRegistration, Refusal> {
    let raw = params
        .get("client_id")
        .ok_or(refuse(ErrorCode::InvalidClient, Reason::MissingParameter))?;
    let client_id = ClientId::parse(raw)
        .map_err(|_| refuse(ErrorCode::InvalidClient, Reason::MalformedParameter))?;
    let client = directory
        .find(tenant, &client_id)
        .filter(|registration| registration.tenant == *tenant)
        .ok_or(refuse(ErrorCode::InvalidClient, Reason::UnknownClient))?;
    reject_method_not_pinned(client.auth_method, presented)?;
    Ok(client)
}

/// The presented method is exactly the pinned one. Secret methods are pinnable but not verifiable yet, so only a
/// public client (`none`) authenticates today; a confidential registration is refused rather than trusted.
fn reject_method_not_pinned(pinned: AuthMethod, presented: PresentedAuth) -> Result<(), Refusal> {
    match (pinned, presented) {
        (AuthMethod::None, PresentedAuth::None) => Ok(()),
        _ => Err(refuse(
            ErrorCode::InvalidClient,
            Reason::AuthMethodNotPinned,
        )),
    }
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
