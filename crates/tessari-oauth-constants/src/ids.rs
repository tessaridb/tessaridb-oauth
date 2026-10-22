/// Longest tenant id, in bytes. A tenant id is the issuer's path segment (`https://<host>/<tenant>`); 63 is one DNS
/// label, which keeps every issuer short and leaves the id usable as a host label.
pub const TENANT_ID_MAX_LEN: usize = 63;

/// Longest client id, in bytes. RFC 6749 sets no bound; this one keeps a value a stranger sends to a public endpoint
/// bounded before it is looked up.
pub const CLIENT_ID_MAX_LEN: usize = 255;

/// Longest user id, in bytes. Ids are assigned by the server, so the bound only keeps a presented value from being
/// unbounded; 64 holds a base64url-encoded 256-bit value with room to spare.
pub const USER_ID_MAX_LEN: usize = 64;

/// The fewest characters a password may have when it is the only factor (NIST SP 800-63B-4 §3.1.1.2), counted in
/// Unicode code points after normalisation.
pub const PASSWORD_MIN_CHARS_ALONE: usize = 15;

/// The fewest characters a password may have when it is used only within multi-factor authentication (same section).
pub const PASSWORD_MIN_CHARS_WITHIN_MFA: usize = 8;

/// The most characters a password may have: well above the 64 the guidance asks to permit, and a bound on what the
/// key-derivation function is handed.
pub const PASSWORD_MAX_CHARS: usize = 256;

/// The longest email address, in bytes: the longest forward path SMTP carries (RFC 5321 §4.5.3.1.3) less its angle
/// brackets.
pub const EMAIL_MAX_LEN: usize = 254;

/// The longest local part of an email address, in bytes (RFC 5321 §4.5.3.1.1).
pub const EMAIL_LOCAL_MAX_LEN: usize = 64;
