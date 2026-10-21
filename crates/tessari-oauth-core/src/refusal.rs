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
    /// `prompt` named `none` together with another value.
    PromptNoneCombined,
    /// `prompt=none` asked for no page, and there is no session to answer it from.
    SilentWithoutSession,
    /// A pushed authorization request named a `request_uri` of its own (RFC 9126 §2.1).
    RequestUriInPush,
    /// A `request_uri` names no pushed request this client may claim: malformed, unknown, lapsed, claimed already,
    /// or another client's.
    RequestUriUnknown,
    /// The client authenticated with a method other than the one pinned at registration.
    AuthMethodNotPinned,
    /// `grant_type` is not one this endpoint redeems.
    UnsupportedGrantType,
    /// The client is not registered for this `grant_type`.
    GrantNotRegistered,
    /// A refresh asked for a scope the original grant does not hold.
    ScopeBeyondGrant,
    /// A client assertion is not a JWS signed by one of the client's keys under its registered algorithm.
    AssertionSignature,
    /// A client assertion's type, issuer, subject or `jti` is not what client authentication requires.
    AssertionClaims,
    /// A client assertion is not addressed to this tenant's issuer alone.
    AssertionAudience,
    /// A client assertion is expired, not yet valid, or valid for longer than allowed.
    AssertionTime,
    /// A DPoP proof is not a `dpop+jwt` signed under an allowed algorithm by the public key it carries.
    DpopProof,
    /// A DPoP proof's `jti`, `htm` or `htu` does not hold for this request.
    DpopClaims,
    /// A DPoP proof is older than the acceptance window or ahead of the clock.
    DpopTime,
    /// A request carried more than one DPoP proof.
    DpopSeveralProofs,
    /// No DPoP proof came from a client registered as bound, or for a refresh token bound to a key.
    DpopMissing,
    /// A DPoP proof had been presented before.
    DpopReplayed,
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
    /// The `resource` named is not one the code was granted for, or is not a resource indicator at all.
    TargetNotGranted,
    /// No `resource` was named and the code was granted for more than one, or for none.
    TargetUnnamed,
    /// A token request body was not `application/x-www-form-urlencoded`, or was larger than the endpoint reads.
    BodyNotForm,
    /// A token request presented more than one client authentication method.
    SeveralAuthMethods,
    /// A client assertion had been presented before.
    AssertionReplayed,
    /// No such authorization code in this tenant.
    CodeUnknown,
    /// The authorization code had already been redeemed.
    CodeReplayed,
    /// The refresh family a code would start had already been revoked for a replay of that code.
    CodeFamilyRevoked,
    /// No such refresh token in this tenant.
    RefreshUnknown,
    /// The refresh token was issued to another client.
    RefreshOtherClient,
    /// The refresh token had already been rotated: its family is now revoked.
    RefreshReused,
    /// The refresh token went unused past its idle bound, or its family is past its absolute one.
    RefreshExpired,
    /// The refresh token's family was revoked.
    RefreshRevoked,
    /// The refresh token is bound to a DPoP key other than the proof's.
    RefreshOtherKey,
    /// A revocation named an access token, which lives out its short lifetime and is never recalled.
    AccessTokenNotRevocable,
}
