//! An owed logout as the delivering worker reads it.

use tessari_oauth_types::{ClientId, UserId};

/// One ended session's clients still to be told, held by the claim that read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The record's id, which `finish` names.
    pub id: String,
    /// The account whose session ended.
    pub user: UserId,
    /// The ended session's public id.
    pub sid: String,
    /// The clients still to be told.
    pub clients: Vec<ClientId>,
    /// How many times it was claimed, this claim included.
    pub attempts: u32,
}
