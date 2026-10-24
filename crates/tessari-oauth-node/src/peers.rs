//! The other regions this server reads the directories of: each region's store reached over its own small pool
//! with the account that region holds for reading its directory and nothing else.

use std::sync::Arc;

use tessari_oauth_constants::PEER_CONNECTIONS;
use tessari_oauth_daemons::Peer;
use tessari_oauth_infrastructure::config::NodeConfig;
use tessari_oauth_infrastructure::tessaridb::{Database, StoreConfig};
use tessari_oauth_storage::Tenancy;
use tessari_oauth_storage::companies::CompanyService;

use crate::Failure;

/// The other regions' directories, each read over its own connections with the peer account.
pub(crate) fn peers(config: &NodeConfig) -> Result<Vec<Peer>, Failure> {
    let Some(settings) = &config.peers else {
        return Ok(Vec::new());
    };
    let authority = settings.authority.as_ref().map(std::fs::read).transpose()?;
    settings
        .regions
        .iter()
        .map(|peer| {
            let database = Database::new(
                StoreConfig {
                    address: peer.address.clone(),
                    user: settings.user.clone(),
                    password: settings.password.clone(),
                    authority: authority.clone(),
                },
                PEER_CONNECTIONS,
            )?;
            let directory = CompanyService::reading(&database, Tenancy::for_region(&peer.region)?);
            Ok(Peer {
                region: peer.region.clone(),
                directory: Arc::new(directory),
            })
        })
        .collect()
}
