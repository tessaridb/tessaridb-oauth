//! What the protocol core answers when it refuses, and why.
//!
//! The answer has two audiences. The caller receives only the specification's `error` code, and at the
//! authorization endpoint only after the redirect URI is proven registered may that answer travel back to the
//! client at all. The precise [`Reason`] goes to the audit log, so a vague answer never costs the investigation
//! its detail and a detailed answer never becomes an oracle.

/// Which check refused, for the audit log. Never sent to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// A protocol parameter appeared more than once.
    DuplicateParameter,
    /// A parameter the step requires was absent.
    MissingParameter,
    /// A parameter did not have its specified shape.
    MalformedParameter,
    /// No client with this id is registered in this tenant.
    UnknownClient,
    /// The presented redirect URI is not one the client registered.
    UnregisteredRedirectUri,
    /// The client registered several redirect URIs and the request named none.
    RedirectUriRequired,
    /// `response_type` is not `code`.
    UnsupportedResponseType,
    /// `code_challenge_method` is not `S256`.
    UnsupportedChallengeMethod,
    /// A requested scope is beyond the client's ceiling.
    ScopeBeyondCeiling,
    /// The client authenticated with a method other than the one pinned at registration.
    AuthMethodNotPinned,
    /// `grant_type` is not one this endpoint redeems.
    UnsupportedGrantType,
    /// The client is not registered for this `grant_type`.
    GrantNotRegistered,
    /// A refresh asked for a scope the original grant does not hold.
    ScopeBeyondGrant,
    /// The code was issued to another client.
    CodeClientMismatch,
    /// The code was issued in another tenant.
    CodeTenantMismatch,
    /// The redirect URI differs from the one the code was issued for.
    CodeRedirectMismatch,
    /// The token request carried no `code_verifier` for a code issued with a challenge.
    VerifierMissing,
    /// The `code_verifier` does not produce the code's challenge.
    VerifierMismatch,
    /// The code outlived its lifetime.
    CodeExpired,
}
