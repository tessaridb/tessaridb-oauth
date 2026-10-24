//! The other regions a server reads the directories of, so a request for a company one of them serves can be sent
//! there. Each region is its own TessariDB deployment; a server reads another region's directory through an account
//! of that region allowed to read the directory and nothing else.

use std::fmt;
use std::path::PathBuf;

use crate::{Error, Result};

/// One other region: its name and its store's wire `host:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRegion {
    /// The region's name, as its own servers are configured with it.
    pub region: String,
    /// Its store's wire `host:port`.
    pub address: String,
}

/// The other regions and the account their directories are read with.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerSettings {
    /// The regions, in the order given; a company two of them name is sent to the first.
    pub regions: Vec<PeerRegion>,
    /// The account each region's store holds for reading its directory.
    pub user: String,
    /// The account's password; never printed.
    pub password: String,
    /// The certificate (PEM) the regions' chains must lead to; absent only for stores on a loopback address.
    pub authority: Option<PathBuf>,
}

impl fmt::Debug for PeerSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerSettings")
            .field("regions", &self.regions)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("authority", &self.authority)
            .finish()
    }
}

/// The values of the peer variables, each `None` when unset.
pub(super) struct PeerVariables {
    pub(super) list: Option<String>,
    pub(super) user: Option<String>,
    pub(super) password: Option<String>,
    pub(super) authority: Option<String>,
}

/// The peer regions `variables` name for a server of `own` region, `None` when no peer is configured.
pub(super) fn peer_settings(variables: PeerVariables, own: &str) -> Result<Option<PeerSettings>> {
    let Some(list) = variables.list else {
        return Ok(None);
    };
    let regions = regions(&list, own).ok_or_else(|| Error::Invalid {
        key: "TESSARIDB_OAUTH_PEERS",
        value: list.clone(),
        reason: "a comma-separated list of region=host:port, each region once and none of them this server's",
    })?;
    Ok(Some(PeerSettings {
        regions,
        user: variables.user.ok_or(Error::Unset {
            key: "TESSARIDB_OAUTH_PEER_USER",
        })?,
        password: variables.password.ok_or(Error::Unset {
            key: "TESSARIDB_OAUTH_PEER_PASSWORD",
        })?,
        authority: variables.authority.map(PathBuf::from),
    }))
}

/// `list` as regions with their stores, when every entry is `region=host:port` and names a region other than `own`
/// once.
fn regions(list: &str, own: &str) -> Option<Vec<PeerRegion>> {
    let mut regions: Vec<PeerRegion> = Vec::new();
    for entry in list.split(',') {
        let (region, address) = entry.trim().split_once('=')?;
        let (host, port) = address.rsplit_once(':')?;
        let fits = !region.is_empty()
            && region != own
            && !host.is_empty()
            && !host.contains('/')
            && port.parse::<u16>().is_ok()
            && regions.iter().all(|known| known.region != region);
        if !fits {
            return None;
        }
        regions.push(PeerRegion {
            region: region.to_owned(),
            address: address.to_owned(),
        });
    }
    Some(regions)
}

#[cfg(test)]
#[path = "peers_tests.rs"]
mod tests;
