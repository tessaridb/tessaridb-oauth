/// The scope that makes a request an OpenID Connect authentication request (OpenID Connect Core §3.1.2.1): a token
/// carrying it speaks for a user who signed in, so it is never granted where nobody did.
pub const OPENID_SCOPE: &str = "openid";

/// The consent policy in force: which claims each scope releases and how the consent screen describes it. A record
/// given under another version covers nothing, so changing what a scope releases means raising this and asking every
/// user again.
pub const CONSENT_POLICY_VERSION: u32 = 1;
