/// Most request counters the counters space holds at once; past it the least recently written are evicted in the
/// committing transaction. A counter lives one window plus one more, so this bounds the distinct (route group, client)
/// pairs counted per two windows; an evicted counter starts again from zero, which only ever favours that client.
pub const THROTTLE_SPACE_MAX_KEYS: u64 = 1_000_000;
