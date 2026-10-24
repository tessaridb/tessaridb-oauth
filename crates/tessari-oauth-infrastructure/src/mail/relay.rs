//! The operator's relay, reached over SMTP submission: the connection protected as configured, signed in when an
//! account is given, every exchange bounded by a timeout. Read once at startup; sending never touches a file.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, CertificateStore, Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use zeroize::Zeroizing;

use crate::config::{MailCredentials, MailSecurity, MailSettings};
use crate::{Error, Result};

use super::{OutgoingMail, Sender};

/// A secret file is readable by its owner only.
const OTHERS_MASK: u32 = 0o077;

/// The relay mail is submitted to, with the sender it is submitted from.
#[derive(Debug)]
pub struct MailRelay {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    sender: Sender,
}

fn unfit(field: &'static str, reason: &'static str) -> Error {
    Error::InvalidConfig { field, reason }
}

/// The relay account, its password read from a file only its owner can read.
fn credentials(account: &MailCredentials) -> Result<Credentials> {
    let unreadable = || unfit("smtp_password_file", "the file cannot be read");
    let metadata = std::fs::metadata(&account.password_file).map_err(|_| unreadable())?;
    if metadata.permissions().mode() & OTHERS_MASK != 0 {
        return Err(unfit(
            "smtp_password_file",
            "readable by group or others; it must be mode 600 or 400",
        ));
    }
    let text =
        Zeroizing::new(std::fs::read_to_string(&account.password_file).map_err(|_| unreadable())?);
    let password = text.trim_end_matches(['\r', '\n']);
    if password.is_empty() {
        return Err(unfit("smtp_password_file", "the file is empty"));
    }
    Ok(Credentials::new(account.user.clone(), password.to_owned()))
}

/// TLS toward `host`: the chain must lead to `authority` alone when one is given, else to the system's roots.
fn tls_parameters(host: &str, authority: Option<&Path>) -> Result<TlsParameters> {
    let mut builder = TlsParameters::builder(host.to_owned());
    if let Some(authority) = authority {
        let unreadable = || unfit("smtp_authority", "the certificate cannot be read");
        let pem = std::fs::read(authority).map_err(|_| unreadable())?;
        let certificate = Certificate::from_pem(&pem)
            .map_err(|_| unfit("smtp_authority", "not a PEM certificate"))?;
        builder = builder
            .certificate_store(CertificateStore::None)
            .add_root_certificate(certificate);
    }
    builder
        .build_rustls()
        .map_err(|_| unfit("smtp_url", "TLS toward the relay cannot be set up"))
}

/// What went wrong, in words that carry neither an address nor the relay's own text.
fn failed(error: &lettre::transport::smtp::Error) -> Error {
    let reason = if error.is_timeout() {
        "the relay did not answer in time"
    } else if error.is_tls() {
        "TLS with the relay failed"
    } else if error.is_permanent() {
        "the relay refused the mail"
    } else if error.is_transient() {
        "the relay deferred the mail"
    } else {
        "the relay could not be reached or required STARTTLS was not offered"
    };
    Error::Mail {
        reason: reason.to_owned(),
    }
}

impl MailRelay {
    /// The relay `settings` name, its password and authority read now; each exchange is given `timeout`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the password file or the authority cannot be read or is unfit.
    pub fn load(settings: &MailSettings, timeout: Duration) -> Result<Self> {
        let host = settings.host.as_str();
        let tls = match settings.security {
            MailSecurity::ImplicitTls => {
                Tls::Wrapper(tls_parameters(host, settings.authority.as_deref())?)
            }
            MailSecurity::StartTls => {
                Tls::Required(tls_parameters(host, settings.authority.as_deref())?)
            }
            MailSecurity::PlainLoopback => Tls::None,
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(settings.port)
            .tls(tls)
            .timeout(Some(timeout));
        if let Some(account) = &settings.credentials {
            builder = builder.credentials(credentials(account)?);
        }
        Ok(Self {
            transport: builder.build(),
            sender: Sender {
                name: settings.from_name.clone(),
                address: settings.from_address.clone(),
            },
        })
    }

    /// Submit `mail`.
    ///
    /// # Errors
    ///
    /// [`Error::Mail`] when the relay cannot be reached in time, refuses the mail, or the mail cannot be built.
    pub async fn send(&self, mail: &OutgoingMail) -> Result<()> {
        let message = mail.message(&self.sender)?;
        self.transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(|error| failed(&error))
    }
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
