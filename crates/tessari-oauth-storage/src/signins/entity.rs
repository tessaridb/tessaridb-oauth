//! `signins` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One sign-in in progress; its record id is the digest of the browser's sign-in cookie value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigninEntity {
    /// The pending authorization the sign-in answers.
    pub interaction: String,
    /// Whether somebody was identified.
    pub identified: bool,
    /// The account identified; absent before identification and for an identifier that names nobody.
    pub user_id: Option<String>,
    /// Whether the identified account has a second factor enrolled.
    pub second_factor: bool,
    /// The methods verified so far, in order.
    pub methods: Vec<String>,
    /// Counts the steps taken; each step is written only over the revision it was taken from.
    pub revision: i64,
    /// Unix seconds the sign-in began.
    pub created_at: i64,
}

impl FromRecord for SigninEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            interaction: row.take("interaction")?,
            identified: row.take("identified")?,
            user_id: row.take("user_id")?,
            second_factor: row.take("second_factor")?,
            methods: row.take("methods")?,
            revision: row.take("revision")?,
            created_at: row.take("created_at")?,
        })
    }
}
