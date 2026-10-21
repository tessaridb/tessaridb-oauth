/// Attempts at spending one authorization code when the store answers `retry`, counting the first. A loser of a
/// simultaneous redemption is told `retry` while the winner's commit is still landing in its group sync; asking
/// again once that commit is readable turns the answer into the replay it is. A bound at all, so contention
/// surfaces as a failure instead of a loop.
pub const CODE_SPEND_ATTEMPTS: u32 = 8;

/// Attempts at spending one client assertion. The spend is a conditional `SET` that the store already re-runs for up
/// to a second when it loses a race; an attempt here answers the `retry` that survives that. A bound at all, as above.
pub const ASSERTION_SPEND_ATTEMPTS: u32 = 8;

/// Attempts at writing one consent record, counting the first. A grant is read, merged and written back under a
/// revision check; each refused attempt means another writer of the same record succeeded, so the bound is the
/// number of simultaneous grants for one user and client that are still served rather than failed.
pub const CONSENT_WRITE_ATTEMPTS: u32 = 32;

/// Pause before a store write is tried again, in milliseconds; each later pause doubles up to
/// [`STORE_RETRY_MAX_PAUSE_MS`]. The first pause is about one device sync, which is what a `retry` is waiting on.
pub const STORE_RETRY_FIRST_PAUSE_MS: u64 = 2;

/// Longest pause between two attempts at one store write, in milliseconds. Eight code-spend attempts wait at most
/// 2 + 4 + … + 64 + 64 = 190 ms in all, inside a token request's budget.
pub const STORE_RETRY_MAX_PAUSE_MS: u64 = 64;

/// Sign-ins one connection pool runs at once. A node verifies at most 24 passwords at a time per process and answers
/// `throttled` beyond that, so a pool opening many connections together signs them in a few at a time rather than
/// spending the node's whole allowance — and leaves room for the other replicas sharing it.
pub const STORE_SIGNIN_CONCURRENCY: usize = 4;

/// Attempts at signing a new connection in when the node answers `throttled` (not now, as opposed to not this
/// password), counting the first.
pub const STORE_SIGNIN_ATTEMPTS: u32 = 6;

/// Attempts at rotating one refresh token when the store answers `retry`, counting the first; as for a code
/// spend, the losing rotation then sees the winner's and is answered as the reuse it is.
pub const REFRESH_ROTATE_ATTEMPTS: u32 = 8;
