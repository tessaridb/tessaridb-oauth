//! The mail a route sends, in its company's wording: the company's own for the kind, else the region's default, else
//! the shipped text, each filled in with the values the kind carries.

use tessari_oauth_core::mail_template::{self, MailKind, Placeholder, Rendered};
use tessari_oauth_storage::outbox::NewMail;
use tessari_oauth_types::{EmailAddress, TenantId};

use crate::state::PublicState;
use crate::{Error, Result};

/// `kind`'s mail to `to` in `tenant`'s wording, filled in with `values`.
pub(super) async fn compose(
    state: &PublicState,
    tenant: &TenantId,
    kind: MailKind,
    to: Option<EmailAddress>,
    values: &[(Placeholder, &str)],
) -> Result<NewMail> {
    let template = state
        .mail_templates
        .resolve(tenant, kind)
        .await
        .map_err(Error::Store)?;
    let Rendered { subject, text } =
        mail_template::compose(kind, &template, values).ok_or(Error::Internal)?;
    Ok(NewMail { to, subject, text })
}
