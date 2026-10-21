/// The paths of a tenant's protocol endpoints, appended to its issuer. Fixed, so a client can derive them from the
/// issuer and the metadata can only ever name the routes the server mounts.
pub const AUTHORIZATION_PATH: &str = "/oauth2/authorize";

/// The token endpoint path (RFC 6749 §3.2).
pub const TOKEN_PATH: &str = "/oauth2/token";

/// The key set path (RFC 8414 `jwks_uri`).
pub const JWKS_PATH: &str = "/oauth2/jwks";
