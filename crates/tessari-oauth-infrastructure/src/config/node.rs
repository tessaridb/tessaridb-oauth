//! The variables the server reads, each checked when it is read: a missing required variable or a value that does
//! not fit stops the start naming the variable, and the value too unless it is a secret — secrets are copied, never
//! parsed, so no refusal can carry one. A variable set to the empty string counts as missing.

use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::str::FromStr;

use tessari_oauth_constants::{
    PASSWORD_HASH_ITERATIONS_FLOOR, PASSWORD_HASH_MEMORY_KIB_FLOOR, PASSWORD_HASH_PARALLELISM_FLOOR,
};
use tessari_oauth_types::{TenantId, TrustedProxies};
use url::{Host, Url};

use super::mail::{MailSettings, MailVariables, mail_settings};
use super::peers::{PeerSettings, PeerVariables, peer_settings};
use crate::custody::PasswordCost;
use crate::{Error, Result};

/// Where the public listener serves and the URL clients know it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicConfig {
    /// The public base URL; a tenant's issuer is this followed by `/` and the tenant id.
    pub url: String,
    /// The socket address the listener binds.
    pub address: SocketAddr,
    /// The listener's certificate chain and private key, PEM; without them it serves in the clear, for a TLS
    /// terminator in front of it.
    pub tls: Option<TlsFiles>,
    /// The proxies whose `X-Forwarded-For` names the client; empty believes no forwarded header.
    pub trusted_proxies: TrustedProxies,
}

/// Where the admin console's own listener serves and the URL operators reach it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminConfig {
    /// The admin console's base URL, an origin apart from the public one; a company's console is this followed by
    /// `/admin/` and the company id.
    pub url: String,
    /// The socket address the admin listener binds.
    pub address: SocketAddr,
    /// The admin listener's certificate chain and private key, PEM; without them it serves in the clear.
    pub tls: Option<TlsFiles>,
}

/// A listener's certificate, given both or neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    /// The certificate chain, PEM.
    pub cert: PathBuf,
    /// The private key, PEM.
    pub key: PathBuf,
}

/// How to reach the store.
#[derive(Clone, PartialEq, Eq)]
pub struct StoreSettings {
    /// The node's wire `host:port`.
    pub address: String,
    /// The account the server signs in with.
    pub user: String,
    /// The account's password; never printed.
    pub password: String,
    /// The certificate (PEM) the node's chain must lead to; absent only for a store on a loopback address.
    pub authority: Option<PathBuf>,
    /// Connections the pool holds at most.
    pub connections: NonZeroUsize,
}

impl fmt::Debug for StoreSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreSettings")
            .field("address", &self.address)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("authority", &self.authority)
            .field("connections", &self.connections)
            .finish()
    }
}

/// How many requests of one class — metadata and key-set reads, or token requests — one client address may make per
/// window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadLimit {
    /// Requests admitted per window.
    pub requests: NonZeroU64,
    /// The window's length, in seconds.
    pub window_secs: NonZeroU64,
}

/// Everything the server needs to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    /// The public listener.
    pub public: PublicConfig,
    /// The admin console's listener.
    pub admin: AdminConfig,
    /// The store.
    pub store: StoreSettings,
    /// The key-encryption key file (32 bytes, readable by the owner only).
    pub kek: PathBuf,
    /// The region whose records this server holds.
    pub region: String,
    /// The other regions whose directories this server reads, when it is told of any.
    pub peers: Option<PeerSettings>,
    /// The mail relay, when mail is configured; without it no mail is sent.
    pub mail: Option<MailSettings>,
    /// The tenants this server is the issuer for.
    pub tenants: Vec<TenantId>,
    /// The read limit on the public routes: metadata, key set and UserInfo.
    pub read_limit: ReadLimit,
    /// The limit on the token endpoint, counted apart from reads.
    pub token_limit: ReadLimit,
    /// The limit on the authorization endpoint, counted apart from reads and tokens.
    pub authorize_limit: ReadLimit,
    /// The limit on the sign-in steps, counted apart from every other group.
    pub login_limit: ReadLimit,
    /// The password pepper file (at least 32 bytes, readable by the owner only); passwords are hashed under it and
    /// the sign-in counters named by keys derived from it.
    pub pepper: PathBuf,
    /// The Argon2id cost new password hashes are made at; never below the floor.
    pub password_cost: PasswordCost,
    /// How many password hashes or checks run at once, each holding the cost's memory.
    pub password_concurrency: NonZeroUsize,
}

/// The environment as a lookup answers it.
struct Variables<Lookup> {
    lookup: Lookup,
}

impl<Lookup: Fn(&str) -> Option<String>> Variables<Lookup> {
    fn optional(&self, key: &'static str) -> Option<String> {
        (self.lookup)(key).filter(|value| !value.is_empty())
    }

    fn required(&self, key: &'static str) -> Result<String> {
        self.optional(key).ok_or(Error::Unset { key })
    }

    fn parsed<T: FromStr>(&self, key: &'static str, default: T, reason: &'static str) -> Result<T> {
        self.optional(key).map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|_| Error::Invalid { key, value, reason })
        })
    }
}

/// `value` as a public base URL: https, nothing after the path, no trailing slash, no credentials.
fn public_url(value: String) -> Result<String> {
    if base_url(&value, |_| false).is_some() {
        Ok(value)
    } else {
        Err(Error::Invalid {
            key: "TESSARIDB_OAUTH_PUBLIC_URL",
            value,
            reason: "an https URL with no query, fragment, credentials or trailing slash",
        })
    }
}

/// `value` as the admin console's base URL: a base URL as [`public_url`] reads one, or `http` on a loopback IP
/// literal for a console served in the clear to this machine alone, at an origin other than `public`'s, so the
/// console's cookies and pages share nothing with the issuer's.
fn admin_url(value: String, public: &str) -> Result<String> {
    // The console's callback is a redirect URI, which takes `http` only on 127.0.0.1 or [::1]: the code it carries
    // then never crosses a network in the clear.
    let loopback = |url: &Url| {
        url.scheme() == "http"
            && match url.host() {
                Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
                Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
                _ => false,
            }
    };
    let apart = base_url(&value, loopback)
        .zip(Url::parse(public).ok())
        .is_some_and(|(admin, public)| admin.origin() != public.origin());
    if apart {
        Ok(value)
    } else {
        Err(Error::Invalid {
            key: "TESSARIDB_OAUTH_ADMIN_URL",
            value,
            reason: "an https URL, or http on 127.0.0.1 or [::1], with no query, fragment, credentials or trailing \
                     slash, at an origin other than the public URL's",
        })
    }
}

/// `value` parsed, when it is an https URL (or one `also` admits) with nothing after the path, no trailing slash and
/// no credentials.
fn base_url(value: &str, also: impl Fn(&Url) -> bool) -> Option<Url> {
    Url::parse(value).ok().filter(|url| {
        (url.scheme() == "https" || also(url))
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && !value.ends_with('/')
    })
}

/// `value` as a comma-separated list of distinct tenant ids.
fn tenants(value: String) -> Result<Vec<TenantId>> {
    let mut seen = HashSet::new();
    let mut tenants = Vec::new();
    for raw in value.split(',') {
        let refusal = match TenantId::parse(raw.trim()) {
            Ok(tenant) if seen.insert(tenant.clone()) => {
                tenants.push(tenant);
                continue;
            }
            Ok(_) => "each tenant once",
            Err(_) => "a comma-separated list of tenant ids",
        };
        return Err(Error::Invalid {
            key: "TESSARIDB_OAUTH_TENANTS",
            value,
            reason: refusal,
        });
    }
    Ok(tenants)
}

/// The proxies named by `TESSARIDB_OAUTH_TRUSTED_PROXIES`; unset trusts none.
fn trusted_proxies(
    variables: &Variables<impl Fn(&str) -> Option<String>>,
) -> Result<TrustedProxies> {
    let Some(value) = variables.optional("TESSARIDB_OAUTH_TRUSTED_PROXIES") else {
        return Ok(TrustedProxies::default());
    };
    TrustedProxies::parse(&value).map_err(|_| Error::Invalid {
        key: "TESSARIDB_OAUTH_TRUSTED_PROXIES",
        value,
        reason: "comma-separated IP addresses or address/prefix networks",
    })
}

/// A listener's certificate and key from the variables `cert_key` and `key_key`, both or neither; neither serves
/// that listener in the clear.
fn listener_tls(
    variables: &Variables<impl Fn(&str) -> Option<String>>,
    cert_key: &'static str,
    key_key: &'static str,
) -> Result<Option<TlsFiles>> {
    let cert = variables.optional(cert_key);
    let key = variables.optional(key_key);
    match (cert, key) {
        (Some(cert), Some(key)) => Ok(Some(TlsFiles {
            cert: cert.into(),
            key: key.into(),
        })),
        (None, None) => Ok(None),
        (Some(_), None) => Err(Error::Unset { key: key_key }),
        (None, Some(_)) => Err(Error::Unset { key: cert_key }),
    }
}

impl NodeConfig {
    /// The configuration from the process environment, after a `.env` file in the working directory for development.
    ///
    /// # Errors
    ///
    /// [`Error::Unset`] naming a missing required variable, [`Error::Invalid`] naming a value that does not fit.
    pub fn from_env() -> Result<Self> {
        // A missing `.env` is the production case and is not an error.
        let _development = dotenvy::dotenv();
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The configuration from the variables `lookup` answers.
    ///
    /// # Errors
    ///
    /// As [`NodeConfig::from_env`].
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let variables = Variables { lookup };
        let public = PublicConfig {
            url: public_url(variables.required("TESSARIDB_OAUTH_PUBLIC_URL")?)?,
            address: variables.parsed(
                "TESSARIDB_OAUTH_PUBLIC_ADDRESS",
                SocketAddr::from(([0, 0, 0, 0], 8443)),
                "a socket address such as 0.0.0.0:8443",
            )?,
            tls: listener_tls(
                &variables,
                "TESSARIDB_OAUTH_TLS_CERT",
                "TESSARIDB_OAUTH_TLS_KEY",
            )?,
            trusted_proxies: trusted_proxies(&variables)?,
        };
        let admin = AdminConfig {
            url: admin_url(
                variables.required("TESSARIDB_OAUTH_ADMIN_URL")?,
                &public.url,
            )?,
            address: variables.parsed(
                "TESSARIDB_OAUTH_ADMIN_ADDRESS",
                SocketAddr::from(([0, 0, 0, 0], 9443)),
                "a socket address such as 0.0.0.0:9443",
            )?,
            tls: listener_tls(
                &variables,
                "TESSARIDB_OAUTH_ADMIN_TLS_CERT",
                "TESSARIDB_OAUTH_ADMIN_TLS_KEY",
            )?,
        };
        let store = StoreSettings {
            address: variables.required("TESSARIDB_OAUTH_STORE")?,
            user: variables.required("TESSARIDB_OAUTH_STORE_USER")?,
            password: variables.required("TESSARIDB_OAUTH_STORE_PASSWORD")?,
            authority: variables
                .optional("TESSARIDB_OAUTH_STORE_AUTHORITY")
                .map(PathBuf::from),
            connections: variables.parsed(
                "TESSARIDB_OAUTH_STORE_CONNECTIONS",
                NonZeroUsize::MIN.saturating_add(15),
                "a whole number of connections above zero",
            )?,
        };
        let read_limit = ReadLimit {
            requests: variables.parsed(
                "TESSARIDB_OAUTH_READ_LIMIT",
                NonZeroU64::MIN.saturating_add(299),
                "a whole number of requests above zero",
            )?,
            window_secs: variables.parsed(
                "TESSARIDB_OAUTH_READ_WINDOW_SECS",
                NonZeroU64::MIN.saturating_add(59),
                "a whole number of seconds above zero",
            )?,
        };
        let token_limit = ReadLimit {
            requests: variables.parsed(
                "TESSARIDB_OAUTH_TOKEN_LIMIT",
                NonZeroU64::MIN.saturating_add(59),
                "a whole number of requests above zero",
            )?,
            window_secs: variables.parsed(
                "TESSARIDB_OAUTH_TOKEN_WINDOW_SECS",
                NonZeroU64::MIN.saturating_add(59),
                "a whole number of seconds above zero",
            )?,
        };
        let authorize_limit = ReadLimit {
            requests: variables.parsed(
                "TESSARIDB_OAUTH_AUTHORIZE_LIMIT",
                NonZeroU64::MIN.saturating_add(119),
                "a whole number of requests above zero",
            )?,
            window_secs: variables.parsed(
                "TESSARIDB_OAUTH_AUTHORIZE_WINDOW_SECS",
                NonZeroU64::MIN.saturating_add(59),
                "a whole number of seconds above zero",
            )?,
        };
        let login_limit = ReadLimit {
            requests: variables.parsed(
                "TESSARIDB_OAUTH_LOGIN_LIMIT",
                NonZeroU64::MIN.saturating_add(29),
                "a whole number of requests above zero",
            )?,
            window_secs: variables.parsed(
                "TESSARIDB_OAUTH_LOGIN_WINDOW_SECS",
                NonZeroU64::MIN.saturating_add(59),
                "a whole number of seconds above zero",
            )?,
        };
        let password_cost = PasswordCost::new(
            variables.parsed(
                "TESSARIDB_OAUTH_PASSWORD_MEMORY_KIB",
                PASSWORD_HASH_MEMORY_KIB_FLOOR,
                "a whole number of KiB",
            )?,
            variables.parsed(
                "TESSARIDB_OAUTH_PASSWORD_ITERATIONS",
                PASSWORD_HASH_ITERATIONS_FLOOR,
                "a whole number of passes",
            )?,
            variables.parsed(
                "TESSARIDB_OAUTH_PASSWORD_PARALLELISM",
                PASSWORD_HASH_PARALLELISM_FLOOR,
                "a whole number of lanes",
            )?,
        )?;
        let region = variables.required("TESSARIDB_OAUTH_REGION")?;
        let peers = peer_settings(
            PeerVariables {
                list: variables.optional("TESSARIDB_OAUTH_PEERS"),
                user: variables.optional("TESSARIDB_OAUTH_PEER_USER"),
                password: variables.optional("TESSARIDB_OAUTH_PEER_PASSWORD"),
                authority: variables.optional("TESSARIDB_OAUTH_PEER_AUTHORITY"),
            },
            &region,
        )?;
        Ok(Self {
            public,
            admin,
            store,
            kek: variables.required("TESSARIDB_OAUTH_KEK")?.into(),
            region,
            peers,
            mail: mail_settings(MailVariables {
                url: variables.optional("TESSARIDB_OAUTH_SMTP_URL"),
                user: variables.optional("TESSARIDB_OAUTH_SMTP_USER"),
                password_file: variables.optional("TESSARIDB_OAUTH_SMTP_PASSWORD_FILE"),
                from: variables.optional("TESSARIDB_OAUTH_SMTP_FROM"),
                authority: variables.optional("TESSARIDB_OAUTH_SMTP_AUTHORITY"),
            })?,
            tenants: tenants(variables.required("TESSARIDB_OAUTH_TENANTS")?)?,
            read_limit,
            token_limit,
            authorize_limit,
            login_limit,
            pepper: variables.required("TESSARIDB_OAUTH_PEPPER")?.into(),
            password_cost,
            password_concurrency: variables.parsed(
                "TESSARIDB_OAUTH_PASSWORD_CONCURRENCY",
                NonZeroUsize::MIN.saturating_add(3),
                "a whole number of hashes above zero",
            )?,
        })
    }
}
