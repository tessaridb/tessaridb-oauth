//! The client credentials grant's own checks (RFC 6749 §4.4), after the client is authenticated and the grant type
//! allowed.
//!
//! No user stands behind the token, so nothing was consented to and nothing is released by default: the client asks
//! for its scopes by name (RFC 6749 §3.3 lets the server refuse an omitted `scope`), within its ceiling, and for one
//! of the resources it registered. It never carries `openid`, which speaks for a user who signed in.

use tessari_oauth_constants::OPENID_SCOPE;
use tessari_oauth_types::{ErrorCode, Resource, ScopeSet};

use crate::clients::ClientRegistration;
use crate::token::{self, Refusal};
use crate::{Params, Reason};

/// What a client-credentials request is granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrant {
    /// The scopes asked for, all within the client's ceiling.
    pub scopes: ScopeSet,
    /// The one resource the token is addressed to.
    pub audience: Resource,
}

/// The grant `params` asks `client` for.
///
/// # Errors
///
/// `invalid_scope` for an absent or malformed `scope`, one beyond the client's ceiling, or `openid`; `invalid_target` for a
/// resource the client did not register, or none named where it registered several.
pub fn grant(params: &Params, client: &ClientRegistration) -> Result<ClientGrant, Refusal> {
    let invalid_scope = |reason| Refusal {
        error: ErrorCode::InvalidScope,
        reason,
    };
    let raw = params
        .get("scope")
        .ok_or(invalid_scope(Reason::MissingParameter))?;
    let scopes = ScopeSet::parse(raw).map_err(|_| invalid_scope(Reason::MalformedParameter))?;
    if !scopes.is_within(&client.scope_ceiling) {
        return Err(invalid_scope(Reason::ScopeBeyondCeiling));
    }
    if scopes.iter().any(|scope| scope == OPENID_SCOPE) {
        return Err(invalid_scope(Reason::OpenIdWithoutUser));
    }
    Ok(ClientGrant {
        scopes,
        audience: token::audience(params, &client.resources)?,
    })
}

#[cfg(test)]
#[path = "client_credentials_tests.rs"]
mod tests;
