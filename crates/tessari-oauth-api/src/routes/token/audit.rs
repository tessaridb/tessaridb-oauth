//! The audit message each outcome leaves: what was issued, named by the token's `jti` and never by the token, or what
//! was refused and why.

use tessari_oauth_core::Reason;
use tessari_oauth_core::access_token::Grant;
use tessari_oauth_core::clients::AuthMethod;
use tessari_oauth_core::token::Refusal;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{ClientId, UserId};

/// The message for an access token minted under `grant` with `jti`, for `user` when one is behind it, to a client
/// that authenticated by `auth_method`.
pub(super) fn issued(
    kind: AuditKind,
    grant: &Grant<'_>,
    jti: String,
    user: Option<&UserId>,
    auth_method: AuthMethod,
) -> AuditEvent {
    AuditEvent {
        client_id: Some(grant.client_id.clone()),
        user: user.cloned(),
        subject: Some(grant.subject.to_owned()),
        scopes: Some(grant.scopes.clone()),
        audience: Some(grant.audience.as_str().to_owned()),
        jti: Some(jti),
        auth_method: Some(auth_method.name().to_owned()),
        bound_to: grant.bound_to.cloned(),
        ..AuditEvent::of(kind)
    }
}

/// The message for `refused`, naming the client the request named: a replayed code and a reused refresh token are
/// kinds of their own, because each means a credential leaked.
pub(super) fn refused(refused: &Refusal, client_id: Option<&ClientId>) -> AuditEvent {
    let kind = match refused.reason {
        Reason::CodeReplayed => AuditKind::CodeReplayed,
        Reason::RefreshReused => AuditKind::RefreshReused,
        _ => AuditKind::Refused,
    };
    AuditEvent {
        client_id: client_id.cloned(),
        reason: Some(format!("{:?}", refused.reason)),
        ..AuditEvent::of(kind)
    }
}
