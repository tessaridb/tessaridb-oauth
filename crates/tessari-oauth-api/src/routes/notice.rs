//! The mail that tells a user their account's sign-in changed, sent to the account's address after the change: so a
//! change somebody else made is seen by the person it was made to. A notice carries no link and no secret. Without a
//! relay nothing is sent; a notice that cannot be queued is logged and never undoes the change it reports.

use tessari_oauth_core::mail_template::{MailKind, Placeholder};
use tessari_oauth_types::{TenantId, UserId};

use super::mail::compose;
use crate::Error;
use crate::state::PublicState;

/// A change to how an account signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Change {
    PasswordChanged,
    PasswordReset,
    PasskeyAdded,
    PasskeyRemoved,
    AppEnrolled,
    AppRemoved,
    RecoveryCodesIssued,
    RecoveryCodeUsed,
    SignedOutEverywhere,
}

impl Change {
    /// The reason the change is recorded under.
    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::PasswordChanged => "password_changed",
            Self::PasswordReset => "password_reset",
            Self::PasskeyAdded => "passkey_added",
            Self::PasskeyRemoved => "passkey_removed",
            Self::AppEnrolled => "totp_enrolled",
            Self::AppRemoved => "totp_removed",
            Self::RecoveryCodesIssued => "recovery_codes_issued",
            Self::RecoveryCodeUsed => "recovery_code_used",
            Self::SignedOutEverywhere => "signed_out_everywhere",
        }
    }

    /// What the notice says happened.
    const fn what(self) -> &'static str {
        match self {
            Self::PasswordChanged => "Its password was changed.",
            Self::PasswordReset => {
                "Its password was changed with a reset link, and every session was signed out."
            }
            Self::PasskeyAdded => "A passkey was added.",
            Self::PasskeyRemoved => "A passkey was removed.",
            Self::AppEnrolled => "An authenticator app was set up.",
            Self::AppRemoved => "Its authenticator app was removed.",
            Self::RecoveryCodesIssued => {
                "New recovery codes were made; the earlier ones no longer work."
            }
            Self::RecoveryCodeUsed => "A recovery code was used to sign in.",
            Self::SignedOutEverywhere => "Every session was signed out.",
        }
    }

    /// The values a notice of this change at `issuer` is filled in with.
    const fn values(self, issuer: &str) -> [(Placeholder, &str); 2] {
        [
            (Placeholder::Issuer, issuer),
            (Placeholder::Change, self.what()),
        ]
    }
}

/// Tell `user` of `tenant` about `change`, at the account's address.
pub(super) async fn notify(state: &PublicState, tenant: &TenantId, user: &UserId, change: Change) {
    if !state.mail {
        return;
    }
    let Some(issuer) = state.served.issuer(tenant) else {
        return;
    };
    let queued = async {
        let account = state.users.find(tenant, user).await.map_err(Error::Store)?;
        let Some(account) = account else {
            return Ok(());
        };
        let mail = compose(
            &state.mail_templates,
            tenant,
            MailKind::SigninChanged,
            Some(account.email),
            &change.values(&issuer),
        )
        .await?;
        state
            .outbox
            .enqueue(tenant, &state.kek, &mail)
            .await
            .map_err(Error::Store)
    };
    if let Err(failure) = queued.await {
        tracing::warn!(
            event = "notice_unqueued",
            tenant = tenant.as_str(),
            change = change.reason(),
            %failure,
            "a notice of a sign-in change could not be queued; the change stands"
        );
    }
}

#[cfg(test)]
#[path = "notice_tests.rs"]
mod tests;
