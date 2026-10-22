/// The paths of a tenant's protocol endpoints, appended to its issuer. Fixed, so a client can derive them from the
/// issuer and the metadata can only ever name the routes the server mounts.
pub const AUTHORIZATION_PATH: &str = "/oauth2/authorize";

/// The sign-in page an authorization request is handed to, appended to the issuer with the pending authorization's
/// id as `interaction`.
pub const LOGIN_PATH: &str = "/login";

/// The consent page a signed-in browser is sent to when the user has not granted what a pending authorization asks,
/// appended to the issuer with the pending authorization's id as `interaction`.
pub const CONSENT_PATH: &str = "/consent";

/// Where the sign-in page's steps are posted, appended to the issuer.
pub const LOGIN_API_PATH: &str = "/login/api";

/// Where, under a tenant's path, the account portal's API is served to a signed-in user.
pub const ACCOUNT_API_PATH: &str = "/account/api";

/// The largest sign-in step body read, in bytes. A passkey assertion is the longest step and stays well under this.
pub const LOGIN_BODY_MAX_BYTES: usize = 16 * 1024;

/// The cookie that binds a sign-in in progress to the browser that began it. The `__Host-` prefix makes a browser
/// keep it only when it is Secure, has Path `/` and names no domain (RFC 6265bis §4.1.3.2).
pub const LOGIN_COOKIE: &str = "__Host-tessari-login";

/// The cookie that carries a user's session at this issuer once a sign-in completes, under the same `__Host-` rules
/// as the sign-in cookie.
pub const SESSION_COOKIE: &str = "__Host-tessari-session";

/// The cookie that names the browser a pending authorization was brought by, so only that browser can sign in for it,
/// answer its consent or receive its code; under the same `__Host-` rules.
pub const BROWSER_COOKIE: &str = "__Host-tessari-browser";

/// Where a browser whose sign-in completed is sent to continue its pending authorization, appended to the issuer
/// with that authorization's id as `interaction`.
pub const AUTHORIZE_RESUME_PATH: &str = "/oauth2/authorize/resume";

/// The largest authorization-request body read when the request is POSTed as a form (OpenID Connect Core
/// §3.1.2.1), in bytes — the same handful of short parameters a query carries.
pub const AUTHORIZE_BODY_MAX_BYTES: usize = 16 * 1024;

/// The pushed authorization request endpoint path (RFC 9126 §2).
pub const PAR_PATH: &str = "/oauth2/par";

/// What a pushed request's id is written after to make its `request_uri` (RFC 9126 §2.2).
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// The token endpoint path (RFC 6749 §3.2).
pub const TOKEN_PATH: &str = "/oauth2/token";

/// The revocation endpoint path (RFC 7009 §2).
pub const REVOCATION_PATH: &str = "/oauth2/revoke";

/// The UserInfo endpoint path (OpenID Connect Core §5.3); appended to the issuer it is also the audience a token for
/// it names, since it is a resource of the server's own.
pub const USERINFO_PATH: &str = "/oauth2/userinfo";

/// The key set path (RFC 8414 `jwks_uri`).
pub const JWKS_PATH: &str = "/oauth2/jwks";

/// The largest token-request body read, in bytes. A token request is a handful of short parameters; a client
/// assertion is the longest and stays well under this. A larger body is refused before it is parsed.
pub const TOKEN_BODY_MAX_BYTES: usize = 16 * 1024;
