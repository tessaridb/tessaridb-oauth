/// Shortest `code_verifier`, in characters (RFC 7636 §4.1). Forty-three unreserved characters carry about 256
/// bits; a shorter verifier is guessable by anybody who saw the challenge, and the challenge travels in a URL.
pub const PKCE_VERIFIER_MIN_LEN: usize = 43;

/// Longest `code_verifier`, in characters (RFC 7636 §4.1). A bound at all, so a stranger cannot hand an unbounded
/// string to a digest.
pub const PKCE_VERIFIER_MAX_LEN: usize = 128;

/// Lifetime of an authorization code, in seconds (RFC 9700 §2.1.1 limits it). Nothing legitimate
/// needs longer: the client redeems the code in the request that receives it.
pub const AUTHORIZATION_CODE_TTL_SECS: u64 = 60;

/// Lifetime of a pending authorization — a validated `/authorize` request waiting for its user to sign in — in
/// seconds: ten minutes, long enough for a login ceremony and short enough that an abandoned one is gone before it
/// could be resumed by someone else. The store expires the record after the same time.
pub const INTERACTION_TTL_SECS: u64 = 600;

/// How long a pushed authorization request (RFC 9126) waits for the browser to bring its `request_uri` to
/// `/authorize`, in seconds — the client redirects the browser the moment it receives the answer (RFC 9126 §2.2 gives
/// sixty seconds as its example). Once claimed, the request lives on as a pending authorization.
pub const PUSHED_REQUEST_TTL_SECS: u64 = 60;

/// Longest a refresh token stays usable without being used, in seconds: 14 days (RFC 9700 §4.14.2 asks for an
/// idle and an absolute bound). Each rotation starts the idle clock again for its successor.
pub const REFRESH_IDLE_TTL_SECS: u64 = 1_209_600;

/// Longest a refresh-token family lives however often it is used, in seconds: 30 days. After it, the user signs in.
pub const REFRESH_ABSOLUTE_TTL_SECS: u64 = 2_592_000;

/// Longest a session at this issuer stays signed in without a request, in seconds: 8 hours, a working day. Each
/// request that finds it starts the clock again.
pub const SESSION_IDLE_SECS: u64 = 28_800;

/// Longest a session at this issuer lasts however often it is used, in seconds: 7 days. After it, the user signs in
/// again; the table's own expiry is the same week.
pub const SESSION_ABSOLUTE_SECS: u64 = 604_800;
