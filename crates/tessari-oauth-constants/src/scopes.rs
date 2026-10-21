/// The scope that makes a request an OpenID Connect authentication request (OpenID Connect Core §3.1.2.1): a token
/// carrying it speaks for a user who signed in, so it is never granted where nobody did.
pub const OPENID_SCOPE: &str = "openid";
