/// The least memory one password hash may use, in KiB: 64 MiB, the second recommended Argon2id option of RFC 9106
/// §4. Measured at 94 ms per hash with the iteration floor below on a ten-core 2021 laptop; configuration may only
/// raise it.
pub const PASSWORD_HASH_MEMORY_KIB_FLOOR: u32 = 65_536;

/// The fewest passes over that memory (RFC 9106 §4, second recommended option).
pub const PASSWORD_HASH_ITERATIONS_FLOOR: u32 = 3;

/// The fewest lanes. One lane costs the attacker the same memory per guess as more lanes would, and this build
/// computes the lanes in turn, so more of them buy no speed.
pub const PASSWORD_HASH_PARALLELISM_FLOOR: u32 = 1;

/// Bytes in a password hash's output: 256 bits, more than any guessable password carries.
pub const PASSWORD_HASH_OUTPUT_BYTES: usize = 32;

/// Bytes of random salt per password hash: 128 bits (RFC 9106 §3.1 recommends 16 bytes).
pub const PASSWORD_SALT_BYTES: usize = 16;

/// The fewest bytes a pepper file may hold: 256 bits, the strength of the HMAC-SHA-256 it keys.
pub const PEPPER_MIN_BYTES: usize = 32;

/// The version of the pepper a node holds, stored beside every password hash it writes. A node holds one pepper,
/// so this is the only version written until a second one exists.
pub const CURRENT_PEPPER: u32 = 1;

/// Where a new password is looked up among passwords seen in breaches when the configuration names no other place:
/// an open service answering a range query (the first five hex digits of the password's SHA-1 go out, never the
/// password or its whole digest).
pub const BREACHED_PASSWORDS_DEFAULT_URL: &str = "https://api.pwnedpasswords.com/range/";

/// The most one breached-password lookup may take, in seconds; past it the password is judged without the list.
pub const BREACHED_PASSWORDS_TIMEOUT_SECS: u64 = 3;

/// The most an answer to one lookup may hold, in bytes; a range answers in tens of KiB.
pub const BREACHED_PASSWORDS_MAX_ANSWER_BYTES: usize = 1_048_576;

/// Hex digits of a password's SHA-1 that a lookup sends (the range query's prefix).
pub const BREACHED_PASSWORDS_PREFIX_DIGITS: usize = 5;
