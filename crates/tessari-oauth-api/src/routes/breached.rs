//! A new password is refused when it was seen in a breach (NIST SP 800-63B-4 §3.1.1.2). The lookup sends only the
//! range prefix of its digest; when it does not answer, the password is judged by the other rules alone and the
//! miss is logged, so an outage of the list never stops anybody setting a password.

use tessari_oauth_core::password::PasswordRefused;

use crate::state::PublicState;
use crate::{Error, Result};

/// `Ok` unless the breached-password list holds `password`.
///
/// # Errors
///
/// [`Error::PasswordRejected`] when the list holds it.
pub(crate) async fn screened(state: &PublicState, password: &str) -> Result<()> {
    let Some(lookups) = &state.breached else {
        return Ok(());
    };
    match lookups.seen(password).await {
        Ok(true) => Err(Error::PasswordRejected(PasswordRefused::Guessable)),
        Ok(false) => Ok(()),
        Err(unchecked) => {
            tracing::warn!(
                event = "breach_check_unchecked",
                reason = %unchecked,
                "a new password was judged without the breached-password list"
            );
            Ok(())
        }
    }
}
