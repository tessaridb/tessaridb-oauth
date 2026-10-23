//! Two regions, each its own TessariDB store: each serves its own company, reads the other's directory through an
//! account that may read that directory and nothing else, and sends a request for the other's company there.
//!
//! Needs, beside the plain node, a second node for the other region: `TESSARIDB_OAUTH_TEST_PEER_STORE`, `_USER` and
//! `_PASSWORD`, signed in as an owner of that store.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::header::LOCATION;
use axum::http::{Request, StatusCode};
use tessari_oauth_api::public_router;
use tessari_oauth_daemons::{Daemon, Peer, PeerDirectories};
use tessari_oauth_infrastructure::tessaridb::{Database, RefusalClass, StoreConfig};
use tessari_oauth_storage::companies::{CompanyService, CompanyStatus, Elsewhere, Served};
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_test_support::{need, plain_node, unique};
use tessari_oauth_types::{TenantId, Timestamp};
use tower::ServiceExt;

use crate::routes::state;

const EU_BASE: &str = "https://eu.id.example.com";
const US_BASE: &str = "https://us.id.example.com";

fn company(id: &str) -> TenantId {
    TenantId::parse(id).expect("a company id")
}

/// The second node, signed in as its owner.
fn peer_node() -> StoreConfig {
    StoreConfig {
        address: need("TESSARIDB_OAUTH_TEST_PEER_STORE").expect("the peer node is named"),
        user: need("TESSARIDB_OAUTH_TEST_PEER_USER").expect("the peer node's user is named"),
        password: need("TESSARIDB_OAUTH_TEST_PEER_PASSWORD")
            .expect("the peer node's password is named"),
        authority: None,
    }
}

/// A region on the node `config` names: its storage, its name, and its one active company with the base URL recorded.
struct Region {
    name: String,
    serves: TenantId,
    base: &'static str,
    owner: StoreConfig,
    storage: Storage,
}

async fn region(owner: StoreConfig, serves: &str, base: &'static str) -> Region {
    let name = unique("live");
    let database = Database::new(owner.clone(), 2).expect("a configuration the pool accepts");
    let storage = Storage::new(&database, &Tenancy::for_region(&name).expect("a region"));
    storage.throttle.prepare().await.expect("counters prepared");
    storage.companies.prepare().await.expect("a directory");
    storage
        .companies
        .create(
            &company(serves),
            serves,
            "regions test",
            Timestamp::from_unix_secs(1_800_000_000),
        )
        .await
        .expect("created");
    assert!(
        storage
            .companies
            .transition(
                &company(serves),
                CompanyStatus::Provisioning,
                CompanyStatus::Active
            )
            .await
            .expect("moved")
    );
    storage
        .provision_company(
            &company(serves),
            base,
            "https://admin.example.com",
            Timestamp::from_unix_secs(1_800_000_000),
        )
        .await
        .expect("provisioned");
    storage
        .companies
        .record_base(base)
        .await
        .expect("the base recorded");
    Region {
        name,
        serves: company(serves),
        base,
        owner,
        storage,
    }
}

/// An account of `region`'s store that may read its directory and nothing else, signed in as it; dropped by
/// [`drop_reader`].
async fn directory_reader(region: &Region) -> (String, StoreConfig) {
    let user = unique("peer");
    let password = unique("pw-");
    // A password is written out in the statement, which is the only form the store accepts for one.
    let define = format!(
        "DEFINE USER {user} ON oauth_{}.directory ROLE viewer PASSWORD '{password}';",
        region.name
    );
    Database::new(region.owner.clone(), 1)
        .expect("a pool")
        .run_unplaced(&define, Vec::new())
        .await
        .expect("the reader declared");
    let reader = StoreConfig {
        address: region.owner.address.clone(),
        user: user.clone(),
        password,
        authority: None,
    };
    (user, reader)
}

async fn drop_reader(region: &Region, user: &str) {
    Database::new(region.owner.clone(), 1)
        .expect("a pool")
        .run_unplaced(&format!("DROP USER {user};"), Vec::new())
        .await
        .expect("the reader dropped");
}

/// What `here`'s router answers `method` at `uri` after one read of `there`'s directory through `reader`.
async fn ask(
    here: &Region,
    there: &Region,
    reader: &StoreConfig,
    method: &str,
    uri: &str,
) -> (StatusCode, Option<String>) {
    let elsewhere = Arc::new(Elsewhere::new());
    let peer = Peer {
        region: there.name.clone(),
        directory: Arc::new(CompanyService::reading(
            &Database::new(reader.clone(), 1).expect("a pool"),
            Tenancy::for_region(&there.name).expect("a region"),
        )),
    };
    let report = PeerDirectories::new(
        vec![peer],
        Arc::clone(&elsewhere),
        Duration::from_secs(5),
        Duration::from_secs(4),
    )
    .run_once()
    .await
    .expect("a run");
    assert_eq!(report.message, "peers=1 answered=1 companies=1");
    let mut public = state(
        &here.storage,
        Limit {
            requests: NonZeroU64::new(1_000).expect("non-zero"),
            window_secs: NonZeroU64::new(60).expect("non-zero"),
        },
    );
    // This region serves its own company and nothing else.
    let served = Served::new(here.base);
    served.replace([here.serves.clone()]);
    public.served = Arc::new(served);
    public.elsewhere = elsewhere;
    let answer = public_router(public)
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from("grant_type=authorization_code"))
                .expect("a request"),
        )
        .await
        .expect("the router answers");
    let location = answer
        .headers()
        .get(LOCATION)
        .map(|value| value.to_str().expect("text").to_owned());
    (answer.status(), location)
}

#[tokio::test]
#[ignore = "needs two TessariDB nodes: TESSARIDB_OAUTH_TEST_STORE and TESSARIDB_OAUTH_TEST_PEER_STORE, each with _USER and _PASSWORD"]
async fn each_region_serves_its_own_company_and_sends_the_others_home() {
    let eu = region(
        plain_node().expect("the plain node is named"),
        "acme",
        EU_BASE,
    )
    .await;
    let us = region(peer_node(), "beta", US_BASE).await;
    let (us_user, us_reader) = directory_reader(&us).await;
    let (eu_user, eu_reader) = directory_reader(&eu).await;

    assert_eq!(
        ask(
            &eu,
            &us,
            &us_reader,
            "GET",
            "/beta/.well-known/openid-configuration?x=1"
        )
        .await,
        (
            StatusCode::TEMPORARY_REDIRECT,
            Some(format!(
                "{US_BASE}/beta/.well-known/openid-configuration?x=1"
            ))
        )
    );
    assert_eq!(
        ask(&eu, &us, &us_reader, "POST", "/beta/oauth2/token").await,
        (
            StatusCode::TEMPORARY_REDIRECT,
            Some(format!("{US_BASE}/beta/oauth2/token"))
        )
    );
    assert_eq!(
        ask(
            &eu,
            &us,
            &us_reader,
            "GET",
            "/acme/.well-known/oauth-authorization-server"
        )
        .await,
        (StatusCode::OK, None),
        "eu serves its own company"
    );
    assert_eq!(
        ask(&us, &eu, &eu_reader, "GET", "/acme/oauth2/jwks").await,
        (
            StatusCode::TEMPORARY_REDIRECT,
            Some(format!("{EU_BASE}/acme/oauth2/jwks"))
        ),
        "and us sends eu's company home"
    );
    assert_eq!(
        ask(&eu, &us, &us_reader, "GET", "/gamma/oauth2/jwks").await,
        (StatusCode::NOT_FOUND, None)
    );

    // The account another region reads with reaches the directory and no company's records.
    let reading = Database::new(us_reader.clone(), 1).expect("a pool");
    let refused = reading
        .run_unplaced(
            &format!(
                "USE NAMESPACE oauth_{} DATABASE t_beta; SELECT * FROM users LIMIT 1;",
                us.name
            ),
            Vec::new(),
        )
        .await;
    // The same account read the directory above, so this is the reach refused, not the account.
    assert!(
        matches!(
            refused,
            Err(tessari_oauth_infrastructure::Error::Refused {
                class: Some(RefusalClass::Forbidden),
                ..
            })
        ),
        "{refused:?}"
    );

    drop_reader(&us, &us_user).await;
    drop_reader(&eu, &eu_user).await;
}
