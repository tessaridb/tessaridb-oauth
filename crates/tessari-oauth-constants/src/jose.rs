/// Longest a client assertion may be valid, in seconds from now. The client signs one per request, so nothing
/// legitimate needs longer, and the bound is also how long its `jti` must be remembered to refuse a replay.
pub const CLIENT_ASSERTION_MAX_TTL_SECS: u64 = 300;

/// How long an access token is valid, in seconds. A signed token cannot be recalled, so this is also the stated
/// revocation latency: a revoked grant stops working at most this long after the refresh that would renew it fails.
pub const ACCESS_TOKEN_TTL_SECS: u64 = 300;

/// How long an ID token may be accepted, in seconds: the client reads it once, in the response that carries it,
/// so minutes are already generous (OpenID Connect Core §3.1.3.7 leaves the bound to the issuer).
pub const ID_TOKEN_TTL_SECS: u64 = 300;

/// Clock difference tolerated between this server and a client, in seconds. Seconds, not minutes: a wider allowance
/// only hides unsynchronised hosts and lengthens every replay window by the same amount.
pub const CLOCK_SKEW_SECS: u64 = 5;

/// Longest `jti` accepted, in characters. A bound at all, so a stranger cannot make the replay store hold an
/// unbounded key.
pub const JTI_MAX_LEN: usize = 256;

/// How long after its `iat` a DPoP proof is accepted, in seconds (RFC 9449 §11.1: seconds or minutes). A proof is
/// made per request, so a minute covers a slow network; it is also how long its `jti` must be remembered.
pub const DPOP_PROOF_WINDOW_SECS: u64 = 60;
