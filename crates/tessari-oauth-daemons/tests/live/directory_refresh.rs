//! Directory refresh: a run makes the node serve exactly the directory's active companies, so a suspension on the
//! store stops the company being served at the next run, and a resumption brings it back.

use std::sync::Arc;
use std::time::Duration;

use tessari_oauth_daemons::{Daemon, DirectoryRefresh};
use tessari_oauth_storage::companies::{CompanyStatus, Served};
use tessari_oauth_types::{TenantId, Timestamp};

use crate::storage;

fn id(raw: &str) -> TenantId {
    TenantId::parse(raw).expect("a tenant id")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_run_serves_exactly_the_active_companies() {
    let storage = storage();
    storage.companies.prepare().await.expect("prepared");
    for raw in ["acme", "initech", "globex"] {
        storage
            .companies
            .create(&id(raw), raw, "configuration", Timestamp::from_unix_secs(1))
            .await
            .expect("created");
    }
    for raw in ["acme", "initech"] {
        assert!(
            storage
                .companies
                .transition(&id(raw), CompanyStatus::Provisioning, CompanyStatus::Active)
                .await
                .expect("activated")
        );
    }
    let served = Arc::new(Served::new("https://id.example.com"));
    // A company nobody activated must not survive a refresh either.
    served.replace([id("stale")]);
    let daemon = DirectoryRefresh {
        companies: Arc::clone(&storage.companies),
        served: Arc::clone(&served),
        interval: Duration::from_secs(5),
        timeout: Duration::from_secs(5),
    };
    let report = daemon.run_once().await.expect("a run");
    assert_eq!(report.message, "companies=2");
    assert!(served.issuer(&id("acme")).is_some());
    assert!(served.issuer(&id("initech")).is_some());
    assert_eq!(served.issuer(&id("globex")), None, "still provisioning");
    assert_eq!(served.issuer(&id("stale")), None);
    assert!(
        storage
            .companies
            .transition(&id("acme"), CompanyStatus::Active, CompanyStatus::Suspended)
            .await
            .expect("suspended")
    );
    daemon.run_once().await.expect("a run");
    assert_eq!(served.issuer(&id("acme")), None, "suspended");
    assert!(served.issuer(&id("initech")).is_some());
}
