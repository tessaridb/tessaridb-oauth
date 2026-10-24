//! `mail_outbox` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One queued mail; everything it says is in `sealed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailEntity {
    /// The recipient and the text, sealed for this record (base64url).
    pub sealed: String,
    /// How many times the record was claimed, counted by the queue.
    pub attempts: Option<i64>,
}

impl FromRecord for MailEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            sealed: row.take("sealed")?,
            attempts: row.take("attempts")?,
        })
    }
}

/// One claimed mail: the record id as the node spells it, and the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimedEntity {
    pub(crate) spelled: String,
    pub(crate) mail: MailEntity,
}

impl FromRecord for ClaimedEntity {
    fn from_row(row: Row) -> Result<Self, MappingFault> {
        let spelled = row.id().to_owned();
        Ok(Self {
            spelled,
            mail: MailEntity::from_row(row)?,
        })
    }
}
