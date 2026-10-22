//! Audit messages as the rest of the server writes and reads them.

use tessari_oauth_types::{ClientId, KeyThumbprint, ScopeSet, Timestamp, UserId};

use crate::operators::OperatorRole;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    /// Tokens issued for an authorization code.
    IssuedCode,
    /// Tokens issued for a refresh token, which rotated.
    IssuedRefresh,
    /// A client's own token issued (client credentials).
    IssuedClient,
    /// A request refused; `reason` says why.
    Refused,
    /// A redeemed authorization code presented again.
    CodeReplayed,
    /// A rotated refresh token presented again.
    RefreshReused,
    /// A client revoked one of its refresh tokens, and with it the family.
    RevokedByClient,
    /// An account event revoked standing families; `reason` names the event, `families` how many.
    Cascade,
    /// A recovery code stood in for the account's second factor at sign-in.
    RecoveryUsed,
    /// A sign-in completed and opened a session at this issuer.
    SignedIn,
    /// A user granted a client the scopes and resources it asked for.
    Consented,
    /// A grant was ended; `reason` names who ended it.
    ConsentRevoked,
    /// A user ended sessions at this issuer; `reason` says which, `families` how many refresh families went with them.
    SessionsEnded,
    /// A user changed their sign-in factors; `reason` says which change, `families` how many refresh families went.
    FactorChanged,
    /// `actor` gave `user` an operator `role`; `reason` says why.
    OperatorGranted,
    /// `actor` took an operator `role` from `user`; `reason` says why.
    OperatorRevoked,
    /// The emergency path gave `user` operator roles outside any operator's authority; `reason` says which path.
    BreakGlass,
}

impl AuditKind {
    /// Every kind.
    pub const ALL: [Self; 17] = [
        Self::IssuedCode,
        Self::IssuedRefresh,
        Self::IssuedClient,
        Self::Refused,
        Self::CodeReplayed,
        Self::RefreshReused,
        Self::RevokedByClient,
        Self::Cascade,
        Self::RecoveryUsed,
        Self::SignedIn,
        Self::Consented,
        Self::ConsentRevoked,
        Self::SessionsEnded,
        Self::FactorChanged,
        Self::OperatorGranted,
        Self::OperatorRevoked,
        Self::BreakGlass,
    ];

    /// The name the message carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssuedCode => "issued_code",
            Self::IssuedRefresh => "issued_refresh",
            Self::IssuedClient => "issued_client",
            Self::Refused => "refused",
            Self::CodeReplayed => "code_replayed",
            Self::RefreshReused => "refresh_reused",
            Self::RevokedByClient => "revoked_by_client",
            Self::Cascade => "cascade",
            Self::RecoveryUsed => "recovery_used",
            Self::SignedIn => "signed_in",
            Self::Consented => "consented",
            Self::ConsentRevoked => "consent_revoked",
            Self::SessionsEnded => "sessions_ended",
            Self::FactorChanged => "factor_changed",
            Self::OperatorGranted => "operator_granted",
            Self::OperatorRevoked => "operator_revoked",
            Self::BreakGlass => "break_glass",
        }
    }

    /// The kind `name` names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }
}

/// One audit message: identifiers and decisions only — never a token, code, verifier, assertion, proof or secret,
/// which this type has no field to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// What happened.
    pub kind: AuditKind,
    /// The client concerned, when one was named.
    pub client_id: Option<ClientId>,
    /// The user the authority was for, by internal id.
    pub user: Option<UserId>,
    /// The `sub` the token carries.
    pub subject: Option<String>,
    /// The scopes granted.
    pub scopes: Option<ScopeSet>,
    /// The resource the token is addressed to.
    pub audience: Option<String>,
    /// The token's `jti`.
    pub jti: Option<String>,
    /// How the client authenticated.
    pub auth_method: Option<String>,
    /// The DPoP key the token is bound to.
    pub bound_to: Option<KeyThumbprint>,
    /// Why: a refusal's reason, or the account event behind a cascade.
    pub reason: Option<String>,
    /// How many refresh families a cascade revoked.
    pub families: Option<u64>,
    /// Who acted, when it was not `user`: an operator's user id, or the emergency path's name.
    pub actor: Option<String>,
    /// The operator role given or taken.
    pub role: Option<OperatorRole>,
}

impl AuditEvent {
    /// A message of `kind` with nothing else said yet.
    #[must_use]
    pub const fn of(kind: AuditKind) -> Self {
        Self {
            kind,
            client_id: None,
            user: None,
            subject: None,
            scopes: None,
            audience: None,
            jti: None,
            auth_method: None,
            bound_to: None,
            reason: None,
            families: None,
            actor: None,
            role: None,
        }
    }
}

/// A message as the trail holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Its place in the trail: dense, in commit order, from 1.
    pub position: u64,
    /// When it was recorded.
    pub at: Timestamp,
    /// What it says.
    pub event: AuditEvent,
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
