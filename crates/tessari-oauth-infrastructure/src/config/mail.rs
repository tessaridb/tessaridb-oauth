//! The mail relay the server submits mail to, when one is configured: `TESSARIDB_OAUTH_SMTP_*`.

use std::net::IpAddr;
use std::path::PathBuf;

use tessari_oauth_types::EmailAddress;
use url::{Host, Url};

use crate::{Error, Result};

/// How the connection to the relay is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailSecurity {
    /// TLS from the first byte (RFC 8314), `smtps://`.
    ImplicitTls,
    /// A plain greeting upgraded by STARTTLS before anything else is sent (RFC 3207), `smtp://`.
    StartTls,
    /// In the clear, to a relay on a loopback address only.
    PlainLoopback,
}

/// The account the relay is signed in to with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailCredentials {
    /// The user name.
    pub user: String,
    /// The file holding the password.
    pub password_file: PathBuf,
}

/// The relay and the sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailSettings {
    /// The relay's host.
    pub host: String,
    /// The relay's port.
    pub port: u16,
    /// How the connection is protected.
    pub security: MailSecurity,
    /// The account, when the relay asks for one.
    pub credentials: Option<MailCredentials>,
    /// The sender's display name, when one is given.
    pub from_name: Option<String>,
    /// The sender's address.
    pub from_address: String,
    /// The certificate (PEM) the relay's chain must lead to; without it the system's roots.
    pub authority: Option<PathBuf>,
}

/// The values of the mail variables, each `None` when unset.
pub(super) struct MailVariables {
    pub(super) url: Option<String>,
    pub(super) user: Option<String>,
    pub(super) password_file: Option<String>,
    pub(super) from: Option<String>,
    pub(super) authority: Option<String>,
}

/// The relay `variables` name, `None` when no relay is configured; any mail setting without `SMTP_URL` is refused.
pub(super) fn mail_settings(variables: MailVariables) -> Result<Option<MailSettings>> {
    let Some(url) = variables.url else {
        let stray = variables.user.is_some()
            || variables.password_file.is_some()
            || variables.from.is_some()
            || variables.authority.is_some();
        return if stray {
            Err(Error::Unset {
                key: "TESSARIDB_OAUTH_SMTP_URL",
            })
        } else {
            Ok(None)
        };
    };
    let (host, port, security) = relay(&url).ok_or_else(|| Error::Invalid {
        key: "TESSARIDB_OAUTH_SMTP_URL",
        value: url.clone(),
        reason: "smtps://host[:port] or smtp://host[:port] (STARTTLS), or smtp://<loopback IP>:port?plain; \
                 no credentials in the URL",
    })?;
    let from = variables.from.ok_or(Error::Unset {
        key: "TESSARIDB_OAUTH_SMTP_FROM",
    })?;
    let (from_name, from_address) = sender(&from).ok_or_else(|| Error::Invalid {
        key: "TESSARIDB_OAUTH_SMTP_FROM",
        value: from.clone(),
        reason: "one address, or a name and one address as Name <address>",
    })?;
    let credentials = match (variables.user, variables.password_file) {
        (Some(user), Some(password_file)) => Some(MailCredentials {
            user,
            password_file: password_file.into(),
        }),
        (None, None) => None,
        (Some(_), None) => {
            return Err(Error::Unset {
                key: "TESSARIDB_OAUTH_SMTP_PASSWORD_FILE",
            });
        }
        (None, Some(_)) => {
            return Err(Error::Unset {
                key: "TESSARIDB_OAUTH_SMTP_USER",
            });
        }
    };
    Ok(Some(MailSettings {
        host,
        port,
        security,
        credentials,
        from_name,
        from_address,
        authority: variables.authority.map(PathBuf::from),
    }))
}

/// The relay's host, port and protection from `value`, when it is one of the accepted forms.
fn relay(value: &str) -> Option<(String, u16, MailSecurity)> {
    let url = Url::parse(value).ok()?;
    let fits = url.username().is_empty()
        && url.password().is_none()
        && matches!(url.path(), "" | "/")
        && url.fragment().is_none();
    if !fits {
        return None;
    }
    let host = url.host()?;
    let (security, default_port) = match (url.scheme(), url.query()) {
        ("smtps", None) => (MailSecurity::ImplicitTls, 465),
        ("smtp", None) => (MailSecurity::StartTls, 587),
        ("smtp", Some("plain")) => {
            let loopback = match host {
                Host::Ipv4(ip) => ip.is_loopback(),
                Host::Ipv6(ip) => ip.is_loopback(),
                // A non-special scheme's host arrives as a name even when it is an IP literal.
                Host::Domain(name) => name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
            };
            if !loopback {
                return None;
            }
            (MailSecurity::PlainLoopback, 0)
        }
        _ => return None,
    };
    let port = url.port().unwrap_or(default_port);
    if port == 0 {
        return None;
    }
    let host = match host {
        Host::Domain(name) => name.to_owned(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    };
    Some((host, port, security))
}

/// `value` as a display name and one address: `address` or `Name <address>`, nothing that could start a second
/// header or a second recipient.
fn sender(value: &str) -> Option<(Option<String>, String)> {
    if value
        .chars()
        .any(|character| character.is_control() || character == ',')
    {
        return None;
    }
    let (name, address) = match value.split_once('<') {
        Some((name, rest)) => {
            let address = rest.strip_suffix('>')?;
            let name = name.trim();
            (
                Some(name.to_owned()).filter(|name| !name.is_empty()),
                address,
            )
        }
        None => (None, value.trim()),
    };
    if address.contains(['<', '>'])
        || name
            .as_deref()
            .is_some_and(|name| name.contains(['<', '>', '"']))
    {
        return None;
    }
    let address = EmailAddress::parse(address).ok()?;
    Some((name, address.as_str().to_owned()))
}

#[cfg(test)]
#[path = "mail_tests.rs"]
mod tests;
