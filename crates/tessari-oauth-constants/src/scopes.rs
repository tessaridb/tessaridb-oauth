/// The scope that makes a request an OpenID Connect authentication request (OpenID Connect Core §3.1.2.1): a token
/// carrying it speaks for a user who signed in, so it is never granted where nobody did.
pub const OPENID_SCOPE: &str = "openid";

/// The consent policy in force: which claims each scope releases and how the consent screen describes it. A record
/// given under another version covers nothing, so changing what a scope releases means raising this and asking every
/// user again.
pub const CONSENT_POLICY_VERSION: u32 = 3;

/// The version of the words the consent screen shows for the policy in force, stored with each grant so a later
/// question about what the user was told has an answer. It moves with the screen's text, which can change without
/// changing what a scope releases.
pub const CONSENT_SHOWN_VERSION: &str = "3";

/// The scope that releases, at UserInfo, the groups a user is in and the roles those groups carry.
pub const GROUPS_SCOPE: &str = "groups";

/// The scope that releases, at UserInfo, the user's name: `name`, `given_name` and `family_name`.
pub const PROFILE_SCOPE: &str = "profile";
