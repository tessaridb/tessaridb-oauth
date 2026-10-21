/// The cache lifetime the key set is served with, in seconds. A verifier may hold a key set this long, so a new key
/// is published at least this long before anything is signed with it (oauth key rotation overlap).
pub const JWKS_MAX_AGE_SECS: u64 = 300;

/// How long one key signs before its successor takes over, in seconds: 30 days.
pub const SIGNING_KEY_LIFETIME_SECS: u64 = 2_592_000;

/// The longest-lived token a signing key signs, in seconds. A superseded key stays published this long after its
/// successor started signing, so every token it signed still verifies. Access tokens live 5 minutes; the margin covers
/// ID tokens and clock skew.
pub const SIGNED_TOKEN_MAX_TTL_SECS: u64 = 3_600;
