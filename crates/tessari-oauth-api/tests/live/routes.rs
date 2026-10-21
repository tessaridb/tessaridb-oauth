//! The metadata and key set routes: what each answers, what each refuses, and the headers on every answer.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tessari_oauth_api::{PublicState, public_router};
use tessari_oauth_infrastructure::custody::{Kek, SigningKey};
use tessari_oauth_infrastructure::tessaridb::StoreConfig;
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::keys::StoredKey;
use tessari_oauth_test_support::{fresh_storage, plain_node, unique};
use tessari_oauth_types::{Algorithm, TenantId, Timestamp};
use tower::ServiceExt;

const NOW: u64 = 1_800_000_000;
const ISSUER: &str = "https://id.example.com/acme";

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn state(storage: &Storage) -> PublicState {
    PublicState {
        keys: Arc::clone(&storage.keys),
        issuers: Arc::new(HashMap::from([(acme(), ISSUER.to_owned())])),
        clock: Arc::new(|| Timestamp::from_unix_secs(NOW)),
    }
}

struct Answer {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Value,
}

async fn get(storage: &Storage, path: &str) -> Answer {
    let response = public_router(state(storage))
        .oneshot(Request::get(path).body(Body::empty()).expect("a request"))
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    let body = serde_json::from_slice(&bytes).expect("a JSON body");
    Answer {
        status,
        headers,
        body,
    }
}

fn header<'a>(answer: &'a Answer, name: &str) -> &'a str {
    answer
        .headers
        .get(name)
        .unwrap_or_else(|| panic!("{name} is set"))
        .to_str()
        .expect("ASCII")
}

/// Every answer, success or refusal, carries the same protective headers.
fn protected(answer: &Answer) {
    assert_eq!(header(answer, "x-content-type-options"), "nosniff");
    assert_eq!(header(answer, "referrer-policy"), "no-referrer");
    assert_eq!(
        header(answer, "content-security-policy"),
        "default-src 'none'; frame-ancestors 'none'"
    );
    assert_eq!(
        header(answer, "strict-transport-security"),
        "max-age=63072000; includeSubDomains"
    );
    assert!(answer.headers.get("server").is_none());
    assert!(answer.headers.get("access-control-allow-origin").is_none());
}

/// Storage over a node that is not there: every store call fails.
fn unreachable_storage() -> Storage {
    let config = StoreConfig {
        address: "127.0.0.1:1".to_owned(),
        user: "nobody".to_owned(),
        password: "nothing".to_owned(),
        authority: None,
    };
    fresh_storage(config, 1).expect("a configuration the pool accepts")
}

fn live_storage() -> Storage {
    fresh_storage(plain_node().expect("the plain node is named"), 2)
        .expect("a configuration the pool accepts")
}

#[tokio::test]
async fn the_metadata_names_the_tenants_issuer_and_is_cacheable() {
    let storage = unreachable_storage();
    let answer = get(&storage, "/acme/.well-known/oauth-authorization-server").await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body["issuer"], ISSUER);
    assert_eq!(answer.body["jwks_uri"], format!("{ISSUER}/oauth2/jwks"));
    assert_eq!(header(&answer, "cache-control"), "public, max-age=300");
    protected(&answer);
}

#[tokio::test]
async fn a_tenant_this_server_does_not_serve_is_not_found_and_not_named_back() {
    let storage = unreachable_storage();
    for path in [
        "/globex/.well-known/oauth-authorization-server",
        "/globex/oauth2/jwks",
        "/NOT%20A%20TENANT/oauth2/jwks",
    ] {
        let answer = get(&storage, path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(answer.body["code"], "not_found", "{path}");
        assert!(!answer.body.to_string().contains("globex"), "{path}");
        protected(&answer);
    }
}

#[tokio::test]
async fn a_key_set_the_store_cannot_answer_is_unavailable_without_detail() {
    let storage = unreachable_storage();
    let answer = get(&storage, "/acme/oauth2/jwks").await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.body["code"], "unavailable");
    assert!(
        !answer.body.to_string().contains("127.0.0.1"),
        "{}",
        answer.body
    );
    assert!(
        answer
            .headers
            .get("cache-control")
            .is_none_or(|value| value == "no-store")
    );
    protected(&answer);
}

fn kek() -> Kek {
    let path = std::env::temp_dir().join(unique("kek"));
    std::fs::write(&path, (0_u8..32).collect::<Vec<u8>>()).expect("written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("owner-only");
    let kek = Kek::load(&path).expect("a key file");
    std::fs::remove_file(&path).expect("removed");
    kek
}

/// A key made at `created_at`, stored for `acme`; its `kid`.
async fn stored_key(storage: &Storage, kek: &Kek, created_at: u64) -> String {
    let (key, pkcs8) = SigningKey::generate(Algorithm::Es256).expect("a key");
    let tenant = acme();
    storage
        .keys
        .add(
            &tenant,
            &StoredKey {
                kid: key.kid().clone(),
                algorithm: Algorithm::Es256,
                sealed: kek
                    .seal(&tenant, key.kid().as_str(), &pkcs8)
                    .expect("sealed"),
                public_jwk: key.public_jwk().expect("a JWK"),
                created_at: Timestamp::from_unix_secs(created_at),
                compromised: false,
            },
        )
        .await
        .expect("recorded");
    key.kid().as_str().to_owned()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_key_set_publishes_exactly_the_rules_keys_and_never_a_withdrawn_one() {
    let storage = live_storage();
    storage
        .tenants
        .provision(&acme())
        .await
        .expect("provisioned");
    let kek = kek();
    let older = stored_key(&storage, &kek, NOW - 1000).await;
    let newer = stored_key(&storage, &kek, NOW - 10).await;
    let burnt = stored_key(&storage, &kek, NOW - 500).await;
    storage
        .keys
        .compromise(
            &acme(),
            &tessari_oauth_types::KeyThumbprint::parse(burnt.clone()).expect("a kid"),
        )
        .await
        .expect("withdrawn");

    let answer = get(&storage, "/acme/oauth2/jwks").await;
    assert_eq!(answer.status, StatusCode::OK);
    let kids: Vec<&str> = answer.body["keys"]
        .as_array()
        .expect("a keys array")
        .iter()
        .map(|key| key["kid"].as_str().expect("a kid"))
        .collect();
    assert_eq!(kids, [older.as_str(), newer.as_str()]);
    assert!(
        !answer.body.to_string().contains("\"d\""),
        "no private member"
    );
    assert_eq!(header(&answer, "cache-control"), "public, max-age=300");
    protected(&answer);
}
