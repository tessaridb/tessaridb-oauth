/// The largest part of a passkey response accepted — client data, authenticator data, attestation object, signature
/// or stored public key — in bytes. An authenticator sends a few hundred bytes; an attestation carrying certificates a
/// few kilobytes; 64 KiB bounds what is parsed long before memory matters.
pub const WEBAUTHN_PART_MAX_BYTES: usize = 65_536;

/// The longest credential id an authenticator may choose (W3C Web Authentication Level 3, §6.5.1: at most 1023 bytes).
pub const WEBAUTHN_CREDENTIAL_ID_MAX_BYTES: usize = 1023;

/// Bytes of the smallest RSA modulus accepted for RS256: 2048 bits (NIST SP 800-131A Rev. 2), the floor below which
/// the verifier refuses every signature, so a weaker key is refused when it is registered rather than at each use.
pub const WEBAUTHN_RSA_MIN_MODULUS_BYTES: usize = 256;

/// Seconds a passkey challenge may be answered in: 300, the timeout W3C Web Authentication Level 3 (§15.1) recommends
/// for a ceremony that asks for user verification. The challenge table expires its records after the same five minutes.
pub const WEBAUTHN_CHALLENGE_TTL_SECS: u64 = 300;
