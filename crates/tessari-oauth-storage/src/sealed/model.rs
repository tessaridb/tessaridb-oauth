//! What a re-seal counts, and the tables it reads.

/// What a re-seal of one company found, value by value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Resealed {
    /// Sealed under the old key and now sealed under the new one.
    pub resealed: u64,
    /// Already opening under the new key; nothing was written.
    pub already: u64,
    /// Opening under neither key, or not a sealed value at all; left as it was.
    pub unopened: u64,
}

/// A table holding values sealed under the key-encryption key, each bound to its own label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// `signing_keys:<kid>`, bound to the kid.
    SigningKeys,
    /// `totp_factors:<user>`, bound to `totp:<user>`.
    TotpFactors,
    /// `totp_pending:<id>`, bound to `totp-pending:<user_id>`.
    TotpPending,
    /// `secrets:<purpose>`, bound to the purpose.
    Secrets,
    /// `mail_outbox:<id>`, bound to `mail:<id>`.
    MailOutbox,
}

impl Family {
    /// Every family, in the order a re-seal walks them.
    pub(crate) const ALL: [Self; 5] = [
        Self::SigningKeys,
        Self::TotpFactors,
        Self::TotpPending,
        Self::Secrets,
        Self::MailOutbox,
    ];

    /// The table's name.
    pub(crate) const fn table(self) -> &'static str {
        match self {
            Self::SigningKeys => "signing_keys",
            Self::TotpFactors => "totp_factors",
            Self::TotpPending => "totp_pending",
            Self::Secrets => "secrets",
            Self::MailOutbox => "mail_outbox",
        }
    }
}
