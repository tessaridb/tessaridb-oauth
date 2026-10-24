//! `logout_deliveries` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One owed logout; its record id is the ended session's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryEntity {
    /// The account whose session ended.
    pub user_id: String,
    /// The ended session's public id.
    pub sid: String,
    /// The clients still to be told.
    pub clients: Vec<String>,
    /// How many times the record was claimed, counted by the queue.
    pub attempts: Option<i64>,
}

impl FromRecord for DeliveryEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            sid: row.take("sid")?,
            clients: row.take("clients")?,
            attempts: row.take("attempts")?,
        })
    }
}

/// One claimed delivery: the record id as the node spells it, and the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimedEntity {
    pub(crate) spelled: String,
    pub(crate) delivery: DeliveryEntity,
}

impl FromRecord for ClaimedEntity {
    fn from_row(row: Row) -> Result<Self, MappingFault> {
        let spelled = row.id().to_owned();
        Ok(Self {
            spelled,
            delivery: DeliveryEntity::from_row(row)?,
        })
    }
}
