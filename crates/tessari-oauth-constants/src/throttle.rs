/// Most counters each of the region's two counter spaces holds at once; past it the least recently written are
/// evicted in the committing transaction. The request counters are held in the store node's memory, so this also
/// bounds what they take there. A request counter lives one window plus one more, so this bounds the distinct
/// (route group, client) pairs counted per two windows; an evicted counter starts again from zero, which only ever
/// favours that client.
pub const THROTTLE_SPACE_MAX_KEYS: u64 = 1_000_000;

/// How long a sign-in failure is remembered, in seconds: a key's failures count from its first failure for this long.
pub const SIGNIN_MEMORY_SECS: u64 = 900;

/// The first hold after the free failures run out, in seconds; each further failure doubles it up to the key's cap.
pub const SIGNIN_FIRST_HOLD_SECS: u64 = 1;

/// Failures an account key takes before it is held.
pub const SIGNIN_FREE_FAILURES_ACCOUNT: u64 = 5;

/// The longest an account key is held, in seconds. Anyone can fail against any account, so this hold is what an
/// attacker can impose on the owner and stays short; escalating to a challenge is the sign-in ceremony's.
pub const SIGNIN_MAX_HOLD_ACCOUNT_SECS: u64 = 60;

/// Failures a source address takes before it is held; many people can share one address.
pub const SIGNIN_FREE_FAILURES_SOURCE: u64 = 50;

/// The longest a source address is held, in seconds.
pub const SIGNIN_MAX_HOLD_SOURCE_SECS: u64 = 900;

/// Failures one credential pair takes before it is held: the same pair tried again is a replayed list, not a typo.
pub const SIGNIN_FREE_FAILURES_PAIR: u64 = 3;

/// The longest a credential pair is held, in seconds.
pub const SIGNIN_MAX_HOLD_PAIR_SECS: u64 = 900;
