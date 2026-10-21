//! Refresh-token families as the rest of the server reads them.

use std::collections::BTreeSet;

use tessari_oauth_types::{ClientId, Resource, ScopeSet, TenantId, UserId};

/// What a refresh token carries: the authority its family was granted, unchanged by rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshGrant {
    /// The tenant the family lives in.
    pub tenant: TenantId,
    /// The user the tokens act for.
    pub user: UserId,
    /// The only client that may present them.
    pub client_id: ClientId,
    /// The scopes granted; a refresh never widens them.
    pub scopes: ScopeSet,
    /// The resources the scopes were granted at.
    pub resources: BTreeSet<Resource>,
}

/// Why a presented token did not rotate, leaving its family as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationRefusal {
    /// No such token.
    Unknown,
    /// The token went unused past its idle bound, or the family is past its absolute one.
    Expired,
    /// The family was revoked — after a reuse, or by its user, an operator or a cascade.
    FamilyRevoked,
    /// The token belongs to another client.
    OtherClient,
}

/// What presenting a refresh token did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotation {
    /// This call spent the token; its successor now carries the same grant.
    Rotated(RefreshGrant),
    /// The token had already been spent: two parties hold the chain, so the whole family is now revoked.
    Reused(RefreshGrant),
    /// Nothing changed.
    Refused(RotationRefusal),
}
