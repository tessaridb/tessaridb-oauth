/// Longest tenant id, in bytes. A tenant id is the issuer's path segment (`https://<host>/<tenant>`); 63 is one DNS
/// label, which keeps every issuer short and leaves the id usable as a host label.
pub const TENANT_ID_MAX_LEN: usize = 63;

/// Longest client id, in bytes. RFC 6749 sets no bound; this one keeps a value a stranger sends to a public endpoint
/// bounded before it is looked up.
pub const CLIENT_ID_MAX_LEN: usize = 255;
