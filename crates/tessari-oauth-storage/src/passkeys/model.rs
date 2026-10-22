//! What the passkey service takes and answers with.

use tessari_oauth_types::UserId;

/// What a registration did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// The credential is stored for the user.
    Created,
    /// A credential with this id is already stored; nothing was written.
    AlreadyRegistered,
}

/// The ceremony a challenge was issued for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    /// Registering a new credential (`webauthn.create`).
    Registration,
    /// Signing in with one (`webauthn.get`).
    Assertion,
}

impl Ceremony {
    /// The word the record stores.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "create",
            Self::Assertion => "get",
        }
    }
}

/// A spent challenge: it was issued for this ceremony and was still current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenged {
    /// The user it was issued to, when the ceremony named one.
    pub user: Option<UserId>,
}

/// A stored credential, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passkey {
    /// The user it belongs to.
    pub user: UserId,
    /// The COSE key as the authenticator sent it.
    pub public_key: Vec<u8>,
    /// The last signature counter the credential reported.
    pub sign_count: u32,
    /// Whether the credential may be synced to other devices.
    pub backup_eligible: bool,
}
