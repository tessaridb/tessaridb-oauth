/// Shortest `code_verifier`, in characters (RFC 7636 §4.1). Forty-three unreserved characters carry about 256
/// bits; a shorter verifier is guessable by anybody who saw the challenge, and the challenge travels in a URL.
pub const PKCE_VERIFIER_MIN_LEN: usize = 43;

/// Longest `code_verifier`, in characters (RFC 7636 §4.1). A bound at all, so a stranger cannot hand an unbounded
/// string to a digest.
pub const PKCE_VERIFIER_MAX_LEN: usize = 128;

/// Lifetime of an authorization code, in seconds (RFC 9700 §2.1.1 limits it; oauth binding 6). Nothing legitimate
/// needs longer: the client redeems the code in the request that receives it.
pub const AUTHORIZATION_CODE_TTL_SECS: u64 = 60;
