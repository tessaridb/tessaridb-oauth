//! Failures of `tessari-oauth-api`, and how each is answered: a status and a stable `code` with a fixed message,
//! never the inner error's text, which may name hosts, tables or records.

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_core::password::PasswordRefused;
use tessari_oauth_types::ErrorCategory;

/// A failure of this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The path names nothing this server serves — an unknown tenant included.
    #[error("not found")]
    NotFound,
    /// The store did not answer.
    #[error("the store did not answer")]
    Store(#[source] tessari_oauth_storage::Error),
    /// A stored value could not be turned into the answer: a defect, not the caller's.
    #[error("an answer could not be built")]
    Internal,
    /// The client made more requests than its limit allows in this window.
    #[error("too many requests")]
    Throttled {
        /// Seconds until the window ends.
        retry_after_secs: u64,
    },
    /// The request could not be read: a body of another shape, or a value outside its grammar.
    #[error("the request could not be read")]
    Invalid,
    /// The browser has no sign-in in progress here: no cookie, one this server never set, or a sign-in that lapsed
    /// or finished.
    #[error("no sign-in in progress")]
    SigninGone,
    /// The step does not belong where the sign-in stands, or the sign-in moved on while it was taken.
    #[error("the step does not belong here")]
    StepRefused,
    /// The password does not prove the account the sign-in identified, or the sign-in identified nobody: one
    /// failure for both, so the answer says nothing about which addresses have accounts.
    #[error("the credentials were not accepted")]
    CredentialsRejected,
    /// The browser holds no session at this issuer, so there is nobody to answer for.
    #[error("no session")]
    SessionRequired,
    /// The session's sign-in is too old, or too weak for what the account holds, to change its sign-in factors.
    #[error("sign in again first")]
    ReauthenticationRequired,
    /// The change would leave the account with no way to sign in.
    #[error("the last way to sign in")]
    LastSignInMethod,
    /// The company's two-factor policy is `off`, so no authenticator app is offered.
    #[error("not offered")]
    NotOffered,
    /// The company's two-factor policy requires a second factor and this is the account's last.
    #[error("a second factor is required")]
    SecondFactorRequired,
    /// The account already holds the factor being enrolled.
    #[error("already enrolled")]
    AlreadyEnrolled,
    /// Nothing is being enrolled for this session: never begun, lapsed, confirmed, or ended by a wrong code.
    #[error("nothing pending")]
    NothingPending,
    /// The code does not come from the secret being enrolled.
    #[error("the code was not accepted")]
    CodeRejected,
    /// No mail relay is configured, so a flow that sends mail is not offered; the same answer for every address.
    #[error("mail is not configured")]
    MailUnavailable,
    /// The new password breaks one of the rules for new passwords.
    #[error("the password was not accepted")]
    PasswordRejected(PasswordRefused),
    /// A profile name is longer than the limit or holds a control character.
    #[error("the profile was not accepted")]
    ProfileRejected,
    /// The address asked for is not one an account can sign in with.
    #[error("the address was not accepted")]
    EmailRejected,
    /// The return to the admin console does not open a session: one answer for every reason, so it says nothing about
    /// which check failed.
    #[error("the console sign-in was refused")]
    ConsoleRefused,
    /// A request that changes state came from another origin than the console's own.
    #[error("cross-origin request")]
    CrossOrigin,
    /// The console operator does not hold the role the request needs.
    #[error("a role is required")]
    RoleRequired,
    /// A console change came without the operator's reason, or with one too long.
    #[error("a reason is required")]
    ReasonRequired,
    /// A console change came without a usable `Idempotency-Key`.
    #[error("an idempotency key is required")]
    IdempotencyKeyRequired,
    /// The `Idempotency-Key` was already used for another change.
    #[error("the idempotency key was used for another change")]
    IdempotencyKeyReused,
    /// The same change is still being made by an earlier request.
    #[error("the change is in progress")]
    ChangeInProgress,
}

impl Error {
    /// The taxonomy category of this failure.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::NotFound => ErrorCategory::NotFound,
            Self::Store(store) => store.category(),
            Self::Internal => ErrorCategory::Internal,
            Self::Throttled { .. } => ErrorCategory::Throttled,
            Self::Invalid => ErrorCategory::Validation,
            Self::SigninGone => ErrorCategory::NotFound,
            Self::StepRefused => ErrorCategory::Conflict,
            Self::CredentialsRejected => ErrorCategory::Unauthorized,
            Self::SessionRequired => ErrorCategory::Unauthorized,
            Self::ReauthenticationRequired => ErrorCategory::Unauthorized,
            Self::LastSignInMethod | Self::NotOffered | Self::SecondFactorRequired => {
                ErrorCategory::Conflict
            }
            Self::AlreadyEnrolled | Self::NothingPending => ErrorCategory::Conflict,
            Self::CodeRejected
            | Self::PasswordRejected(_)
            | Self::ProfileRejected
            | Self::EmailRejected => ErrorCategory::Validation,
            Self::ConsoleRefused | Self::CrossOrigin | Self::RoleRequired => {
                ErrorCategory::Forbidden
            }
            Self::ReasonRequired | Self::IdempotencyKeyRequired => ErrorCategory::Validation,
            Self::IdempotencyKeyReused | Self::ChangeInProgress => ErrorCategory::Conflict,
            Self::MailUnavailable => ErrorCategory::Unavailable,
        }
    }
}

/// The body of every refusal.
#[derive(Serialize)]
struct Body {
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if let Self::Throttled { retry_after_secs } = self {
            // RFC 9110 §10.2.3: the wait in whole seconds.
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after_secs.to_string())],
                Json(Body {
                    code: "rate_limited",
                    message: "too many requests; try again after the stated wait",
                }),
            )
                .into_response();
        }
        let (status, code, message) = match (&self, self.category()) {
            (Self::SigninGone, _) => (
                StatusCode::GONE,
                "signin_expired",
                "the sign-in has expired; start again from the application",
            ),
            (Self::Invalid, _) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the request could not be read",
            ),
            (Self::StepRefused, _) => (
                StatusCode::CONFLICT,
                "step_refused",
                "this step does not belong where the sign-in stands",
            ),
            (Self::CredentialsRejected, _) => (
                StatusCode::UNAUTHORIZED,
                "credentials_rejected",
                "the address or the password is not right",
            ),
            (Self::SessionRequired, _) => (
                StatusCode::UNAUTHORIZED,
                "session_required",
                "sign in first",
            ),
            (Self::ReauthenticationRequired, _) => (
                StatusCode::UNAUTHORIZED,
                "reauthentication_required",
                "sign in again to change how this account signs in",
            ),
            (Self::LastSignInMethod, _) => (
                StatusCode::CONFLICT,
                "last_sign_in_method",
                "this is the account's last way to sign in",
            ),
            (Self::NotOffered, _) => (
                StatusCode::CONFLICT,
                "not_offered",
                "this company does not use a second factor",
            ),
            (Self::SecondFactorRequired, _) => (
                StatusCode::CONFLICT,
                "second_factor_required",
                "this company requires a second factor; add another before removing this one",
            ),
            (Self::AlreadyEnrolled, _) => (
                StatusCode::CONFLICT,
                "already_enrolled",
                "this account already has one",
            ),
            (Self::NothingPending, _) => (StatusCode::CONFLICT, "nothing_pending", "start again"),
            (Self::CodeRejected, _) => (
                StatusCode::BAD_REQUEST,
                "code_rejected",
                "the code was not accepted; start again",
            ),
            (Self::MailUnavailable, _) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "mail_unavailable",
                "this server does not send mail; ask an administrator",
            ),
            (Self::PasswordRejected(rule), _) => (
                StatusCode::BAD_REQUEST,
                "password_rejected",
                match rule {
                    PasswordRefused::TooShort => "the password is too short",
                    PasswordRefused::TooLong => "the password is too long",
                    PasswordRefused::NotPrintable => {
                        "the password holds a character that is not printable"
                    }
                    PasswordRefused::Guessable => "the password is too easily guessed",
                },
            ),
            (Self::ProfileRejected, _) => (
                StatusCode::BAD_REQUEST,
                "profile_rejected",
                "a name must be at most 100 characters with no control character",
            ),
            (Self::EmailRejected, _) => (
                StatusCode::BAD_REQUEST,
                "email_rejected",
                "the address is not one an account can sign in with",
            ),
            (Self::ConsoleRefused, _) => (
                StatusCode::FORBIDDEN,
                "console_refused",
                "this sign-in does not open the admin console; start again",
            ),
            (Self::CrossOrigin, _) => (
                StatusCode::FORBIDDEN,
                "cross_origin",
                "the request did not come from the console",
            ),
            (Self::RoleRequired, _) => (
                StatusCode::FORBIDDEN,
                "role_required",
                "your operator roles do not include this",
            ),
            (Self::ReasonRequired, _) => (
                StatusCode::BAD_REQUEST,
                "reason_required",
                "say why, in 1 to 500 characters",
            ),
            (Self::IdempotencyKeyRequired, _) => (
                StatusCode::BAD_REQUEST,
                "idempotency_key_required",
                "send an Idempotency-Key of 16 to 128 letters, digits, '-' or '_'",
            ),
            (Self::IdempotencyKeyReused, _) => (
                StatusCode::CONFLICT,
                "idempotency_key_reused",
                "this Idempotency-Key was used for another change",
            ),
            (Self::ChangeInProgress, _) => (
                StatusCode::CONFLICT,
                "change_in_progress",
                "this change is still being made; try again shortly",
            ),
            (_, ErrorCategory::NotFound) => {
                (StatusCode::NOT_FOUND, "not_found", "nothing is served here")
            }
            (_, ErrorCategory::Unavailable | ErrorCategory::Timeout) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "try again later",
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "the server could not answer",
            ),
        };
        if status.is_server_error() {
            tracing::error!(error = %self, source = ?std::error::Error::source(&self), "a request failed");
        }
        (status, Json(Body { code, message })).into_response()
    }
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
