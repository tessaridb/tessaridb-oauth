/// The paths of a tenant's protocol endpoints, appended to its issuer. Fixed, so a client can derive them from the
/// issuer and the metadata can only ever name the routes the server mounts.
pub const AUTHORIZATION_PATH: &str = "/oauth2/authorize";

/// The sign-in page an authorization request is handed to, appended to the issuer with the pending authorization's
/// id as `interaction`.
pub const LOGIN_PATH: &str = "/login";

/// The largest authorization-request body read when the request is POSTed as a form (OpenID Connect Core
/// §3.1.2.1), in bytes — the same handful of short parameters a query carries.
pub const AUTHORIZE_BODY_MAX_BYTES: usize = 16 * 1024;

/// The token endpoint path (RFC 6749 §3.2).
pub const TOKEN_PATH: &str = "/oauth2/token";

/// The revocation endpoint path (RFC 7009 §2).
pub const REVOCATION_PATH: &str = "/oauth2/revoke";

/// The key set path (RFC 8414 `jwks_uri`).
pub const JWKS_PATH: &str = "/oauth2/jwks";

/// The largest token-request body read, in bytes. A token request is a handful of short parameters; a client
/// assertion is the longest and stays well under this. A larger body is refused before it is parsed.
pub const TOKEN_BODY_MAX_BYTES: usize = 16 * 1024;
