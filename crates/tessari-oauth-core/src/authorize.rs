//! `/authorize` validation in the fixed order (RFC 9700 §4.1, OpenID Connect Core §3.1.2.2).
//!
//! The order is a security property. Until the client is known and the redirect URI is proven to be one it
//! registered, nothing may be sent to the redirect URI: an error redirected earlier sends the victim, with `state`,
//! to whatever URI the attacker put in the request — an open redirector on the most trusted domain there is. So
//! every refusal up to and including the redirect check is rendered at the server, and only the refusals after it
//! travel back to the client, carrying `state` and the issuer (RFC 9207).

use std::collections::BTreeSet;

use tessari_oauth_types::{Challenge, ClientId, ErrorCode, Resource, ScopeSet, TenantId};

use crate::clients::{ClientDirectory, ClientRegistration};
use crate::{Params, Reason, token};

/// The response type this server issues: the authorization code, and nothing in the front channel.
pub(crate) const RESPONSE_TYPE_CODE: &str = "code";

/// The only PKCE transform accepted (RFC 7636 §4.2).
pub(crate) const CHALLENGE_METHOD_S256: &str = "S256";

/// The `prompt` value asking that no page be shown (OpenID Connect Core §3.1.2.1).
const PROMPT_NONE: &str = "none";

/// An authorization request that passed every check and may go on to the login ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// The client that asked.
    pub client_id: ClientId,
    /// The redirect URI as the request named it (or the single registered one), to be repeated at redemption.
    pub redirect_uri: String,
    /// The scopes requested, within the client's ceiling.
    pub scopes: ScopeSet,
    /// The PKCE challenge to store with the code.
    pub challenge: Challenge,
    /// The client's `state`, echoed unchanged.
    pub state: Option<String>,
    /// The resources the code will grant (RFC 8707): the one named, or the client's only registered one.
    pub resources: BTreeSet<Resource>,
    /// The client's `nonce` (OpenID Connect Core §3.1.2.1), echoed unchanged into the ID token.
    pub nonce: Option<String>,
    /// The client asked that no page be shown (`prompt=none`): the request is answered from an existing session or
    /// refused, never sent to sign in.
    pub silent: bool,
}

/// Why an authorization request was refused, and where the answer may go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Shown to the user at the server; the client is unknown or the redirect URI unproven.
    RenderAtServer {
        /// The `error` value shown.
        error: ErrorCode,
        /// The check that refused, for the audit log.
        reason: Reason,
    },
    /// Returned to the client at its registered redirect URI.
    RedirectToClient {
        /// The redirect URI the error is delivered to — one the client registered.
        redirect_uri: String,
        /// The `error` value.
        error: ErrorCode,
        /// The client's `state`, echoed unchanged.
        state: Option<String>,
        /// This tenant's issuer, so a client talking to several servers can tell which one answered.
        iss: String,
        /// The check that refused, for the audit log.
        reason: Reason,
    },
}

/// Validate an authorization request for `tenant`, whose issuer is `issuer`.
///
/// # Errors
///
/// Returns the [`Refusal`] of the first check that fails, in the order the module documents.
pub fn validate<I, K, V>(
    tenant: &TenantId,
    issuer: &str,
    directory: &impl ClientDirectory,
    pairs: I,
) -> Result<AuthorizationRequest, Refusal>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    // Steps 1-4: everything up to the proven redirect URI renders at the server.
    let params = Params::from_pairs(pairs).map_err(|_| render(Reason::DuplicateParameter))?;
    let client = resolve_client(tenant, directory, &params)?;
    let redirect_uri = resolve_redirect_uri(&client, &params)?;

    // Steps 5-7: the redirect URI is the client's own, so refusals travel back to it.
    let state = params.get("state").map(str::to_owned);
    let redirect = |error: ErrorCode, reason: Reason| Refusal::RedirectToClient {
        redirect_uri: redirect_uri.clone(),
        error,
        state: state.clone(),
        iss: issuer.to_owned(),
        reason,
    };
    reject_unsupported_response_type(&params).map_err(|(error, reason)| redirect(error, reason))?;
    let challenge =
        require_s256_challenge(&params).map_err(|(error, reason)| redirect(error, reason))?;
    let scopes = reject_scope_beyond_ceiling(&client.scope_ceiling, &params)
        .map_err(|(error, reason)| redirect(error, reason))?;
    // The same rule the token endpoint applies: the one named, or the client's only registered resource.
    let resource = token::audience(&params, &client.resources)
        .map_err(|refused| redirect(refused.error, refused.reason))?;
    // Step 8: the OpenID Connect parameters.
    let silent =
        reject_prompt_none_combined(&params).map_err(|(error, reason)| redirect(error, reason))?;

    Ok(AuthorizationRequest {
        client_id: client.client_id,
        redirect_uri,
        scopes,
        challenge,
        state,
        resources: BTreeSet::from([resource]),
        nonce: params.get("nonce").map(str::to_owned),
        silent,
    })
}

/// A refusal shown at the server, before the redirect URI is proven.
const fn render(reason: Reason) -> Refusal {
    Refusal::RenderAtServer {
        error: ErrorCode::InvalidRequest,
        reason,
    }
}

/// Step 2: the client, found in THIS tenant, or a refusal rendered at the server.
fn resolve_client(
    tenant: &TenantId,
    directory: &impl ClientDirectory,
    params: &Params,
) -> Result<ClientRegistration, Refusal> {
    let raw = params
        .get("client_id")
        .ok_or(render(Reason::MissingParameter))?;
    let client_id = ClientId::parse(raw).map_err(|_| render(Reason::MalformedParameter))?;
    directory
        .find(tenant, &client_id)
        .filter(|registration| registration.tenant == *tenant)
        .ok_or(render(Reason::UnknownClient))
}

/// Step 4: the redirect URI the request names, proven registered; or the single registered one when none is named.
fn resolve_redirect_uri(client: &ClientRegistration, params: &Params) -> Result<String, Refusal> {
    match params.get("redirect_uri") {
        Some(presented) => client
            .redirect_uris
            .iter()
            .any(|registered| registered.matches(presented))
            .then(|| presented.to_owned())
            .ok_or(render(Reason::UnregisteredRedirectUri)),
        None => match client.redirect_uris.as_slice() {
            [only] => Ok(only.as_str().to_owned()),
            _ => Err(render(Reason::RedirectUriRequired)),
        },
    }
}

/// Step 5: `response_type` is exactly `code`.
fn reject_unsupported_response_type(params: &Params) -> Result<(), (ErrorCode, Reason)> {
    match params.get("response_type") {
        None => Err((ErrorCode::InvalidRequest, Reason::MissingParameter)),
        Some(RESPONSE_TYPE_CODE) => Ok(()),
        Some(_) => Err((
            ErrorCode::UnsupportedResponseType,
            Reason::UnsupportedResponseType,
        )),
    }
}

/// Step 6: a well-formed challenge under `S256`; an absent method means `plain` and is refused.
fn require_s256_challenge(params: &Params) -> Result<Challenge, (ErrorCode, Reason)> {
    let raw = params
        .get("code_challenge")
        .ok_or((ErrorCode::InvalidRequest, Reason::MissingParameter))?;
    if params.get("code_challenge_method") != Some(CHALLENGE_METHOD_S256) {
        return Err((
            ErrorCode::InvalidRequest,
            Reason::UnsupportedChallengeMethod,
        ));
    }
    Challenge::parse(raw).map_err(|_| (ErrorCode::InvalidRequest, Reason::MalformedParameter))
}

/// Step 7: the requested scopes, well-formed and within the client's ceiling.
fn reject_scope_beyond_ceiling(
    ceiling: &ScopeSet,
    params: &Params,
) -> Result<ScopeSet, (ErrorCode, Reason)> {
    let raw = params
        .get("scope")
        .ok_or((ErrorCode::InvalidScope, Reason::MissingParameter))?;
    let scopes =
        ScopeSet::parse(raw).map_err(|_| (ErrorCode::InvalidScope, Reason::MalformedParameter))?;
    if !scopes.is_within(ceiling) {
        return Err((ErrorCode::InvalidScope, Reason::ScopeBeyondCeiling));
    }
    Ok(scopes)
}

/// Step 8: whether `prompt` is `none` alone, which asks that no page be shown; `none` beside any other value
/// contradicts itself (OpenID Connect Core §3.1.2.1).
fn reject_prompt_none_combined(params: &Params) -> Result<bool, (ErrorCode, Reason)> {
    let Some(prompt) = params.get("prompt") else {
        return Ok(false);
    };
    if !prompt.split(' ').any(|value| value == PROMPT_NONE) {
        return Ok(false);
    }
    if prompt != PROMPT_NONE {
        return Err((ErrorCode::InvalidRequest, Reason::PromptNoneCombined));
    }
    Ok(true)
}

#[cfg(test)]
#[path = "authorize_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "authorize_prompt_tests.rs"]
mod prompt_tests;
