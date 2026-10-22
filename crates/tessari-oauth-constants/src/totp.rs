/// The length of one time step, in seconds (RFC 6238 §5.2, the default every authenticator app uses).
pub const TOTP_STEP_SECS: u64 = 30;

/// Digits in a one-time code (RFC 4226 §5.3; six is what authenticator apps show).
pub const TOTP_DIGITS: usize = 6;

/// Steps either side of the current one a code is still accepted in (RFC 6238 §5.2 recommends at most one).
pub const TOTP_SKEW_STEPS: u64 = 1;

/// Bytes of a shared secret: 160 bits, the length RFC 4226 §4 requirement R6 recommends for HMAC-SHA-1.
pub const TOTP_SECRET_BYTES: usize = 20;
