//! Tenant provisioning on TessariDB.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place};

use super::repository::TenantRepository;
use crate::Result;

/// The tables of a tenant's database. Every definition carries `IF NOT EXISTS`, so provisioning is re-runnable.
///
/// `codes` holds the bindings of each issued authorization code under the code's digest; `redeemed_at` is absent
/// until the single redemption sets it.
const TABLES: &str = "DEFINE TABLE IF NOT EXISTS codes (\
     tenant string REQUIRED, client_id string REQUIRED, redirect_uri string REQUIRED, \
     challenge string REQUIRED, scopes array REQUIRED, expires_at int REQUIRED, redeemed_at int);";

pub(crate) struct TessaridbTenantRepository {
    database: Database,
}

impl TessaridbTenantRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl TenantRepository for TessaridbTenantRepository {
    async fn provision(&self, place: &Place) -> Result<()> {
        // Names are checked plain by `Place`, which is what allows them into the text; nothing else is.
        // The containers are declared before the transaction: on 0.36.2 a `USE` of a namespace declared inside the
        // still-open transaction is refused as outside the user's reach. Each container declaration is re-runnable
        // on its own; the tables, which belong together, go in one transaction.
        let namespace = place.namespace();
        let database = place.database();
        let script = format!(
            "DEFINE NAMESPACE IF NOT EXISTS {namespace}; USE NAMESPACE {namespace}; \
             DEFINE DATABASE IF NOT EXISTS {database}; USE DATABASE {database}; BEGIN; {TABLES} COMMIT;"
        );
        self.database.run_unplaced(&script, Vec::new()).await?;
        Ok(())
    }
}
