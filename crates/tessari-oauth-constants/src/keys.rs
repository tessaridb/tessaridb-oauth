/// The cache lifetime the key set is served with, in seconds. A verifier may hold a key set this long, so a new key
/// is published at least this long before anything is signed with it (oauth key rotation overlap).
pub const JWKS_MAX_AGE_SECS: u64 = 300;

/// How long one key signs before its successor takes over, in seconds: 30 days.
pub const SIGNING_KEY_LIFETIME_SECS: u64 = 2_592_000;

/// The longest-lived token a signing key signs, in seconds. A superseded key stays published this long after its
/// successor started signing, so every token it signed still verifies. Access tokens live 5 minutes; the margin covers
/// ID tokens and clock skew.
pub const SIGNED_TOKEN_MAX_TTL_SECS: u64 = 3_600;

/// How many tenants one rotation run works on at once. Each tenant costs a few small store round trips, so this
/// bounds the run's share of the connection pool rather than its CPU.
pub const KEY_ROTATION_CONCURRENCY: usize = 8;

/// How often the rotation daemon checks every tenant's keys, in seconds. A successor is due well inside a key's
/// lifetime, so checking every five minutes only bounds how late after its due time a key is made.
pub const KEY_ROTATION_CHECK_SECS: u64 = 300;

/// The most one rotation run may take, in seconds, before it is abandoned and the next run tries again.
pub const KEY_ROTATION_RUN_TIMEOUT_SECS: u64 = 60;
