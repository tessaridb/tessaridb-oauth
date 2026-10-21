//! A tenant's client registrations: registered once, found by id in their own tenant only, and a key that is not a
//! public signing key refused before anything is written.

use std::collections::BTreeSet;

use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_types::{
    Algorithm, ClientId, ErrorCategory, RedirectUri, Resource, ScopeSet, TenantId, Timestamp,
};

use crate::fresh;

/// RFC 8037 §A.2: an Ed25519 public key.
const ED25519_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn service_client(id: &str, jwks: Vec<String>) -> NewClient {
    NewClient {
        client_id: ClientId::parse(id).expect("a client id"),
        redirect_uris: vec![
            RedirectUri::parse("https://app.example.com/cb").expect("a redirect URI"),
        ],
        scope_ceiling: ScopeSet::parse("orders:read orders:write").expect("scopes"),
        resources: BTreeSet::new(),
        auth_method: AuthMethod::PrivateKeyJwt(Algorithm::EdDsa),
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        jwks,
        dpop_bound_access_tokens: false,
    }
}

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_registered_client_is_found_whole_in_its_own_tenant_only() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    let registered = storage
        .clients
        .register(
            &tenant("acme"),
            &service_client("svc-1", vec![ED25519_JWK.to_owned()]),
            NOW,
        )
        .await
        .expect("registered");
    let found = storage
        .clients
        .find(
            &tenant("acme"),
            &ClientId::parse("svc-1").expect("a client id"),
        )
        .await
        .expect("answered")
        .expect("found");
    assert_eq!(found, registered);
    assert_eq!(found.tenant, tenant("acme"));
    assert_eq!(
        found.redirect_uris[0].as_str(),
        "https://app.example.com/cb"
    );
    assert_eq!(
        found.auth_method,
        AuthMethod::PrivateKeyJwt(Algorithm::EdDsa)
    );
    assert_eq!(
        found.grant_types,
        [GrantType::AuthorizationCode, GrantType::RefreshToken]
    );
    assert_eq!(found.keys.len(), 1);
    let elsewhere = storage
        .clients
        .find(
            &tenant("globex"),
            &ClientId::parse("svc-1").expect("a client id"),
        )
        .await
        .expect("answered");
    assert!(
        elsewhere.is_none(),
        "a client is not found in another tenant"
    );
    let unknown = storage
        .clients
        .find(
            &tenant("acme"),
            &ClientId::parse("nobody").expect("a client id"),
        )
        .await
        .expect("answered");
    assert!(unknown.is_none());
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_id_is_registered_once() {
    let storage = fresh(&tenant("acme"), 2).await;
    let client = service_client("svc-1", vec![ED25519_JWK.to_owned()]);
    storage
        .clients
        .register(&tenant("acme"), &client, NOW)
        .await
        .expect("registered");
    let again = storage
        .clients
        .register(&tenant("acme"), &client, NOW)
        .await;
    assert!(
        matches!(&again, Err(error) if error.category() == ErrorCategory::Conflict),
        "{again:?}"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_key_that_is_not_a_public_signing_key_is_refused_before_anything_is_written() {
    let storage = fresh(&tenant("acme"), 2).await;
    let private = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#;
    for jwks in [
        vec![private.to_owned()],
        vec!["not a key".to_owned()],
        Vec::new(),
    ] {
        let refused = storage
            .clients
            .register(&tenant("acme"), &service_client("svc-2", jwks.clone()), NOW)
            .await;
        assert!(
            matches!(&refused, Err(error) if error.category() == ErrorCategory::Validation),
            "{jwks:?}: {refused:?}"
        );
    }
    let found = storage
        .clients
        .find(
            &tenant("acme"),
            &ClientId::parse("svc-2").expect("a client id"),
        )
        .await
        .expect("answered");
    assert!(found.is_none());
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_registered_dpop_bound_is_found_bound_and_one_registered_plain_is_not() {
    let storage = fresh(&tenant("acme"), 2).await;
    let mut bound = service_client("svc-bound", vec![ED25519_JWK.to_owned()]);
    bound.dpop_bound_access_tokens = true;
    let plain = service_client("svc-plain", vec![ED25519_JWK.to_owned()]);
    for client in [&bound, &plain] {
        let registered = storage
            .clients
            .register(&tenant("acme"), client, NOW)
            .await
            .expect("registered");
        let found = storage
            .clients
            .find(&tenant("acme"), &client.client_id)
            .await
            .expect("answered")
            .expect("found");
        assert_eq!(
            found.dpop_bound_access_tokens,
            client.dpop_bound_access_tokens,
            "{}",
            client.client_id.as_str()
        );
        assert_eq!(found, registered);
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_clients_resources_are_found_as_registered() {
    let storage = fresh(&tenant("acme"), 2).await;
    let mut client = service_client("svc-res", vec![ED25519_JWK.to_owned()]);
    client.resources = BTreeSet::from([
        Resource::parse("https://api.example.com/").expect("a resource"),
        Resource::parse("https://files.example.com/").expect("a resource"),
    ]);
    storage
        .clients
        .register(&tenant("acme"), &client, NOW)
        .await
        .expect("registered");
    let found = storage
        .clients
        .find(&tenant("acme"), &client.client_id)
        .await
        .expect("answered")
        .expect("found");
    assert_eq!(found.resources, client.resources);
}
