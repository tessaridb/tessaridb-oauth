//! The refresh grant's own checks (RFC 6749 §6), after the client is authenticated and the grant type allowed.
//!
//! A refresh never gains authority: a `scope` asking for anything the original grant does not hold is refused, not
//! quietly narrowed to what the grant holds, so a client learns that it asked for too much. The rotation itself, with
//! reuse detection, is the storage layer's atomic step.

use tessari_oauth_types::{ErrorCode, RefreshToken, ScopeSet};

use crate::token::Refusal;
use crate::{Params, Reason};

/// The refresh token the request presents.
///
/// # Errors
///
/// `invalid_request` when `refresh_token` is absent.
pub fn presented(params: &Params) -> Result<RefreshToken, Refusal> {
    params
        .get("refresh_token")
        .map(RefreshToken::from_secret)
        .ok_or(Refusal {
            error: ErrorCode::InvalidRequest,
            reason: Reason::MissingParameter,
        })
}

/// The scopes of the refreshed grant: the original grant's when `scope` is absent, else the requested subset.
///
/// # Errors
///
/// `invalid_scope` for a malformed `scope` or one naming a scope `granted` does not hold.
pub fn scopes(params: &Params, granted: &ScopeSet) -> Result<ScopeSet, Refusal> {
    let Some(raw) = params.get("scope") else {
        return Ok(granted.clone());
    };
    let asked = ScopeSet::parse(raw).map_err(|_| Refusal {
        error: ErrorCode::InvalidScope,
        reason: Reason::MalformedParameter,
    })?;
    if !asked.is_within(granted) {
        return Err(Refusal {
            error: ErrorCode::InvalidScope,
            reason: Reason::ScopeBeyondGrant,
        });
    }
    Ok(asked)
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod tests;
