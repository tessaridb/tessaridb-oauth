/// The base64url alphabet of RFC 4648 §5 — the URL-safe one, with `-` and `_` as its last two characters.
pub const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Characters in a SHA-256 digest written as unpadded base64url: 32 bytes are exactly 43 characters. Both an S256
/// PKCE challenge (RFC 7636 §4.2) and a JWK thumbprint (RFC 7638 §3) have this length, so a value of any other
/// length is a digest of another function rather than a short one.
pub const SHA256_BASE64URL_LEN: usize = 43;
