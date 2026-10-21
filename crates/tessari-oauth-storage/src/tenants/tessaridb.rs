//! Tenant provisioning on TessariDB.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place};

use super::repository::TenantRepository;
use crate::Result;

/// The tables of a tenant's database. Every definition carries `IF NOT EXISTS`, so provisioning is re-runnable.
///
/// `codes` holds the bindings of each issued authorization code under the code's digest; `redeemed_at` is absent
/// until the single redemption sets it. `consents` holds one grant per user and client; it is indexed by user because
/// a user's grant list is read by user, while every check reads one record by its id. `refresh_families` and
/// `refresh_tokens` hold each family and each of its tokens under a digest; every read is by id.
const TABLES: &str = "DEFINE TABLE IF NOT EXISTS codes (\
     tenant string REQUIRED, client_id string REQUIRED, user_id string REQUIRED, redirect_uri string REQUIRED, \
     challenge string REQUIRED, scopes array REQUIRED, expires_at int REQUIRED, redeemed_at int); \
     DEFINE TABLE IF NOT EXISTS consents (\
     tenant string REQUIRED, user_id string REQUIRED, client_id string REQUIRED, scopes array REQUIRED, \
     resources array REQUIRED, policy_version int REQUIRED, shown_version string REQUIRED, \
     granted_at int REQUIRED, revision int REQUIRED, revoked_at int, revoked_by string); \
     DEFINE INDEX IF NOT EXISTS by_user ON consents FIELDS user_id; \
     DEFINE TABLE IF NOT EXISTS refresh_families (\
     tenant string REQUIRED, client_id string REQUIRED, user_id string REQUIRED, created_at int REQUIRED, \
     expires_at int REQUIRED, revoked_at int, revoked_reason string); \
     DEFINE TABLE IF NOT EXISTS refresh_tokens (\
     family_id string REQUIRED, tenant string REQUIRED, client_id string REQUIRED, user_id string REQUIRED, \
     scopes array REQUIRED, resources array REQUIRED, idle_expires_at int REQUIRED, rotated_at int);";

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
