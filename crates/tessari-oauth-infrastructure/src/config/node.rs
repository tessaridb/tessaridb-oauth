//! The variables the server reads, each checked when it is read: a missing required variable or a value that does
//! not fit stops the start naming the variable, and the value too unless it is a secret — secrets are copied, never
//! parsed, so no refusal can carry one. A variable set to the empty string counts as missing.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::str::FromStr;

use tessari_oauth_types::TenantId;
use url::Url;

use crate::{Error, Result};

/// Where the public listener serves and the URL clients know it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicConfig {
    /// The public base URL; a tenant's issuer is this followed by `/` and the tenant id.
    pub url: String,
    /// The socket address the listener binds.
    pub address: SocketAddr,
    /// The listener's certificate chain, PEM.
    pub tls_cert: PathBuf,
    /// The listener's private key, PEM.
    pub tls_key: PathBuf,
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

/// How many metadata and key-set reads one client address may make per window.
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
    /// The store.
    pub store: StoreSettings,
    /// The key-encryption key file (32 bytes, readable by the owner only).
    pub kek: PathBuf,
    /// The region whose records this server holds.
    pub region: String,
    /// The tenants this server is the issuer for.
    pub tenants: Vec<TenantId>,
    /// The read limit on the public routes.
    pub read_limit: ReadLimit,
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
    let fits = Url::parse(&value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
    }) && !value.ends_with('/');
    if fits {
        Ok(value)
    } else {
        Err(Error::Invalid {
            key: "TESSARIDB_OAUTH_PUBLIC_URL",
            value,
            reason: "an https URL with no query, fragment, credentials or trailing slash",
        })
    }
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
            tls_cert: variables.required("TESSARIDB_OAUTH_TLS_CERT")?.into(),
            tls_key: variables.required("TESSARIDB_OAUTH_TLS_KEY")?.into(),
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
        Ok(Self {
            public,
            store,
            kek: variables.required("TESSARIDB_OAUTH_KEK")?.into(),
            region: variables.required("TESSARIDB_OAUTH_REGION")?,
            tenants: tenants(variables.required("TESSARIDB_OAUTH_TENANTS")?)?,
            read_limit,
        })
    }
}
