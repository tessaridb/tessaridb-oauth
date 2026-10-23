//! The wording the server ships with, one subject and text per kind; a company may replace any of them.

use super::MailKind;

/// The subject and text of `kind` as shipped.
pub(super) const fn wording(kind: MailKind) -> (&'static str, &'static str) {
    match kind {
        MailKind::Reset => (
            "Reset your password",
            "Someone asked to reset the password of your account at {issuer}.\n\n\
             To choose a new password, open this link within 30 minutes:\n{link}\n\n\
             Your second factor and passkeys stay as they are.\n\
             If you did not ask, ignore this mail; your password does not change.\n",
        ),
        MailKind::Verify => (
            "Confirm your email address",
            "Someone asked to confirm this address for an account at {issuer}.\n\n\
             To confirm it, open this link within 24 hours:\n{link}\n\n\
             If you did not ask, ignore this mail; nothing changes.\n",
        ),
        MailKind::EmailConfirm => (
            "Confirm your new sign-in address",
            "Someone asked to sign in to an account at {issuer} with this address instead of the one it uses now.\n\n\
             To confirm it, open this link within 24 hours:\n{link}\n\n\
             The change takes effect a day after it was asked for, unless it is cancelled from the old address.\n\
             If you did not ask, ignore this mail; nothing changes.\n",
        ),
        MailKind::EmailTaken => (
            "Confirm your new sign-in address",
            "Someone asked to sign in to another account at {issuer} with this address.\n\n\
             This address already signs in to an account there, so nothing changes and it stays with that account.\n\
             If you did not expect this, you can ignore it.\n",
        ),
        MailKind::EmailCancel => (
            "Your sign-in address is changing",
            "Someone signed in to your account at {issuer} asked to change the address it signs in with to \
             {new_address}.\n\n\
             The change takes effect 24 hours after it was asked for, once the new address confirms it.\n\
             If you did not ask, cancel it with this link before then, and change your password:\n{link}\n",
        ),
        MailKind::EmailAppliedOld => (
            "Your sign-in address has changed",
            "Your account at {issuer} now signs in with {new_address} instead of this address.\n\n\
             If you did not ask for this, contact the administrator of that sign-in service.\n",
        ),
        MailKind::EmailAppliedNew => (
            "Your sign-in address has changed",
            "Your account at {issuer} now signs in with this address.\n",
        ),
        MailKind::EmailRefused => (
            "Your sign-in address was not changed",
            "The change of the address your account at {issuer} signs in with did not take effect, and this \
             address still signs in.\n\nYou can ask for the change again from your account page.\n",
        ),
        MailKind::SigninChanged => (
            "Your sign-in changed",
            "Something changed in how your account at {issuer} signs in.\n\n{change}\n\n\
             If you did not do this, tell your administrator.\n",
        ),
        MailKind::Enrolment => (
            "Set the password of your new account",
            "An account at {issuer} was opened for this address.\n\n\
             To choose its password, open this link within 72 hours:\n{link}\n\n\
             The link works once. If you did not expect this, ignore this mail; nobody can sign in until a password \
             is set.\n",
        ),
    }
}
