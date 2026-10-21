/// Attempts at spending one authorization code when the store answers `retry`, counting the first. A loser of a
/// simultaneous redemption is told `retry` while the winner's commit is still landing in its group sync; asking
/// again once that commit is readable turns the answer into the replay it is. A bound at all, so contention
/// surfaces as a failure instead of a loop.
pub const CODE_SPEND_ATTEMPTS: u32 = 8;

/// Pause before the second spend attempt, in milliseconds; each later pause doubles. Eight attempts wait at most
/// 2 + 4 + … + 128 = 254 ms in all, well inside a token request's budget, and the first pause is about one device
/// sync.
pub const CODE_SPEND_FIRST_PAUSE_MS: u64 = 2;
