//! Service credentials: a service is registered once per company with one Ed25519 key and the `users` role alone,
//! a company holds a bounded set, and another company never sees it.

use tessari_oauth_storage::Storage;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::service_credentials::NewService;
use tessari_oauth_types::{ErrorCategory, ServiceId, TenantId, Timestamp};

use crate::fresh;

const NOW: u64 = 1_800_000_000;
const ED25519: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
const P256: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

fn tenant(raw: &str) -> TenantId {
    TenantId::parse(raw).expect("a tenant id")
}

fn id(raw: &str) -> ServiceId {
    ServiceId::parse(raw).expect("a service id")
}

fn backend(name: &str, jwk: &str, roles: Vec<OperatorRole>) -> NewService {
    NewService {
        id: id(name),
        public_jwk: jwk.to_owned(),
        roles,
        registered_by: "operator-1".to_owned(),
        reason: "the cloud backend".to_owned(),
    }
}

async fn register(storage: &Storage, at: &TenantId, service: &NewService) -> bool {
    storage
        .services
        .register(at, service, Timestamp::from_unix_secs(NOW))
        .await
        .is_ok()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_service_is_registered_once_found_listed_and_removed() {
    let storage = fresh(&tenant("acme"), 2).await;
    let made = storage
        .services
        .register(
            &tenant("acme"),
            &backend("backend", ED25519, vec![OperatorRole::Users]),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("registered");
    assert_eq!(made.roles, vec![OperatorRole::Users]);
    let again = storage
        .services
        .register(
            &tenant("acme"),
            &backend("backend", ED25519, vec![OperatorRole::Users]),
            Timestamp::from_unix_secs(NOW),
        )
        .await;
    assert!(
        matches!(&again, Err(error) if error.category() == ErrorCategory::Conflict),
        "a taken id conflicts: {again:?}"
    );
    let found = storage
        .services
        .find(&tenant("acme"), &id("backend"))
        .await
        .expect("an answer")
        .expect("the service");
    assert_eq!(found.registered_by, "operator-1");
    let listed = storage
        .services
        .list(&tenant("acme"))
        .await
        .expect("an answer");
    assert_eq!(listed.len(), 1);
    assert!(
        storage
            .services
            .remove(&tenant("acme"), &id("backend"))
            .await
            .expect("an answer")
    );
    assert!(
        !storage
            .services
            .remove(&tenant("acme"), &id("backend"))
            .await
            .expect("an answer")
    );
    assert!(
        storage
            .services
            .find(&tenant("acme"), &id("backend"))
            .await
            .expect("an answer")
            .is_none()
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_service_outside_the_rules_writes_nothing() {
    let storage = fresh(&tenant("acme"), 2).await;
    let cases = [
        backend("no-roles", ED25519, Vec::new()),
        backend("clients", ED25519, vec![OperatorRole::Clients]),
        backend(
            "keys",
            ED25519,
            vec![OperatorRole::Users, OperatorRole::Keys],
        ),
        backend("companies", ED25519, vec![OperatorRole::Companies]),
        backend("ec-key", P256, vec![OperatorRole::Users]),
        backend("no-key", "{}", vec![OperatorRole::Users]),
    ];
    for case in &cases {
        assert!(
            !register(&storage, &tenant("acme"), case).await,
            "{} must be refused",
            case.id.as_str()
        );
    }
    assert!(
        storage
            .services
            .list(&tenant("acme"))
            .await
            .expect("an answer")
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_company_holds_a_bounded_set_and_never_sees_another_companys() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("initech"))
        .await
        .expect("provisioned");
    for number in 0..20 {
        let name = format!("svc-{number}");
        assert!(
            register(
                &storage,
                &tenant("acme"),
                &backend(&name, ED25519, vec![OperatorRole::Users])
            )
            .await
        );
    }
    assert!(
        !register(
            &storage,
            &tenant("acme"),
            &backend("one-more", ED25519, vec![OperatorRole::Users])
        )
        .await,
        "the twenty-first is refused"
    );
    assert_eq!(
        storage
            .services
            .list(&tenant("acme"))
            .await
            .expect("an answer")
            .len(),
        20
    );
    assert!(
        storage
            .services
            .list(&tenant("initech"))
            .await
            .expect("an answer")
            .is_empty()
    );
    assert!(
        storage
            .services
            .find(&tenant("initech"), &id("svc-0"))
            .await
            .expect("an answer")
            .is_none()
    );
}
