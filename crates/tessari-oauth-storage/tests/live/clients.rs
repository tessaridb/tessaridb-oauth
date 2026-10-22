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
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
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

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn only_a_confidential_client_registers_the_client_credentials_grant() {
    let storage = fresh(&tenant("acme"), 2).await;
    let mut public = service_client("svc-public", Vec::new());
    public.auth_method = AuthMethod::None;
    public.grant_types = vec![GrantType::ClientCredentials];
    let refused = storage
        .clients
        .register(&tenant("acme"), &public, NOW)
        .await;
    assert!(
        matches!(&refused, Err(error) if error.category() == ErrorCategory::Validation),
        "{refused:?}"
    );
    let written = storage
        .clients
        .find(&tenant("acme"), &public.client_id)
        .await
        .expect("answered");
    assert!(written.is_none(), "nothing is written for a refused client");

    let mut confidential = service_client("svc-machine", vec![ED25519_JWK.to_owned()]);
    confidential.grant_types = vec![GrantType::ClientCredentials];
    storage
        .clients
        .register(&tenant("acme"), &confidential, NOW)
        .await
        .expect("a confidential client registers it");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_clients_post_logout_redirect_uris_are_found_as_registered() {
    let storage = fresh(&tenant("acme"), 2).await;
    let mut client = service_client("svc-out", vec![ED25519_JWK.to_owned()]);
    client.post_logout_redirect_uris =
        vec![RedirectUri::parse("https://app.example.com/signed-out").expect("a redirect URI")];
    storage
        .clients
        .register(&tenant("acme"), &client, NOW)
        .await
        .expect("registered");
    let none = service_client("svc-none", vec![ED25519_JWK.to_owned()]);
    storage
        .clients
        .register(&tenant("acme"), &none, NOW)
        .await
        .expect("registered");
    for registered in [&client, &none] {
        let found = storage
            .clients
            .find(&tenant("acme"), &registered.client_id)
            .await
            .expect("answered")
            .expect("found");
        assert_eq!(
            found.post_logout_redirect_uris,
            registered.post_logout_redirect_uris
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_clients_backchannel_logout_uri_is_found_as_registered() {
    let storage = fresh(&tenant("acme"), 2).await;
    let mut told = service_client("svc-told", vec![ED25519_JWK.to_owned()]);
    told.backchannel_logout_uri =
        Some(RedirectUri::parse("https://app.example.com/backchannel").expect("a URI"));
    let untold = service_client("svc-untold", vec![ED25519_JWK.to_owned()]);
    for client in [&told, &untold] {
        storage
            .clients
            .register(&tenant("acme"), client, NOW)
            .await
            .expect("registered");
    }
    for registered in [&told, &untold] {
        let found = storage
            .clients
            .find(&tenant("acme"), &registered.client_id)
            .await
            .expect("answered")
            .expect("found");
        assert_eq!(
            found.backchannel_logout_uri,
            registered.backchannel_logout_uri
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn registrations_are_paged_in_id_order_in_their_own_tenant_only() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    for id in ["svc-3", "svc-1", "svc-2"] {
        storage
            .clients
            .register(
                &tenant("acme"),
                &service_client(id, vec![ED25519_JWK.to_owned()]),
                NOW,
            )
            .await
            .expect("registered");
    }
    storage
        .clients
        .register(
            &tenant("globex"),
            &service_client("svc-0", vec![ED25519_JWK.to_owned()]),
            NOW,
        )
        .await
        .expect("registered");
    let ids = |page: Vec<tessari_oauth_core::clients::ClientRegistration>| {
        page.into_iter()
            .map(|client| client.client_id.as_str().to_owned())
            .collect::<Vec<_>>()
    };
    let first = storage
        .clients
        .page(&tenant("acme"), None, 2)
        .await
        .expect("a page");
    assert_eq!(ids(first), ["svc-1", "svc-2"]);
    let after = ClientId::parse("svc-2").expect("a client id");
    let rest = storage
        .clients
        .page(&tenant("acme"), Some(&after), 2)
        .await
        .expect("a page");
    assert_eq!(ids(rest), ["svc-3"]);
    let other = storage
        .clients
        .page(&tenant("globex"), None, 10)
        .await
        .expect("a page");
    assert_eq!(ids(other), ["svc-0"]);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn removing_a_client_ends_every_grant_and_family_it_held_and_nothing_else() {
    use tessari_oauth_core::consents::ConsentRequest;
    use tessari_oauth_storage::consents::{NewGrant, Revoker};
    use tessari_oauth_storage::refresh::{Holder, RefreshGrant};
    use tessari_oauth_types::{RefreshToken, UserId};

    let storage = fresh(&tenant("acme"), 2).await;
    for id in ["svc-1", "svc-2"] {
        storage
            .clients
            .register(
                &tenant("acme"),
                &service_client(id, vec![ED25519_JWK.to_owned()]),
                NOW,
            )
            .await
            .expect("registered");
    }
    let user = |id: &str| UserId::parse(id).expect("a user id");
    let client = |id: &str| ClientId::parse(id).expect("a client id");
    for (who, to) in [
        ("user-7", "svc-1"),
        ("user-8", "svc-1"),
        ("user-7", "svc-2"),
    ] {
        storage
            .consents
            .grant(&NewGrant {
                tenant: tenant("acme"),
                user: user(who),
                client_id: client(to),
                request: ConsentRequest {
                    scopes: ScopeSet::parse("orders:read").expect("scopes"),
                    resources: BTreeSet::new(),
                },
                policy_version: 1,
                shown_version: "descriptions-v1".to_owned(),
                at: NOW,
            })
            .await
            .expect("granted");
    }
    for (name, to) in [("f1", "svc-1"), ("f2", "svc-2")] {
        let grant = RefreshGrant {
            tenant: tenant("acme"),
            user: user("user-7"),
            client_id: client(to),
            scopes: ScopeSet::parse("orders:read").expect("scopes"),
            resources: BTreeSet::new(),
            bound_to: None,
        };
        storage
            .refresh
            .start(
                &RefreshToken::from_secret(format!("refresh-secret-{name}")),
                &grant,
                &format!("family-{name}"),
                NOW,
            )
            .await
            .expect("started");
    }
    assert_eq!(
        storage
            .consents
            .holders(&tenant("acme"), &client("svc-1"))
            .await
            .expect("counted"),
        2
    );

    let removed = storage
        .remove_client(&tenant("acme"), &client("svc-1"), NOW)
        .await
        .expect("removed");
    assert_eq!(
        (removed.registered, removed.consents, removed.families),
        (true, 2, 1)
    );
    let gone = storage
        .clients
        .find(&tenant("acme"), &client("svc-1"))
        .await
        .expect("answered");
    assert!(gone.is_none(), "the registration is gone");
    for who in ["user-7", "user-8"] {
        let grants = storage
            .consents
            .list(&tenant("acme"), &user(who))
            .await
            .expect("listed");
        let ended = grants
            .iter()
            .find(|consent| consent.client_id == client("svc-1"))
            .expect("the grant is kept as revoked");
        assert_eq!(
            ended
                .revoked
                .as_ref()
                .map(|revocation| revocation.by.clone()),
            Some(Revoker::ClientRemoved)
        );
    }
    assert_eq!(
        storage
            .consents
            .holders(&tenant("acme"), &client("svc-2"))
            .await
            .expect("counted"),
        1,
        "another client's grants stand"
    );
    let standing = storage
        .refresh
        .revoke_standing(
            &tenant("acme"),
            &Holder::Client(&client("svc-2")),
            "probe",
            NOW,
        )
        .await
        .expect("counted");
    assert_eq!(standing, 1, "another client's family stood");
    let again = storage
        .remove_client(&tenant("acme"), &client("svc-1"), NOW)
        .await
        .expect("answered");
    assert_eq!(
        (again.registered, again.consents, again.families),
        (false, 0, 0),
        "a removal sent again finds nothing left to end"
    );
    let console = storage
        .remove_client(&tenant("acme"), &client("admin-console"), NOW)
        .await;
    assert!(
        matches!(&console, Err(error) if error.category() == ErrorCategory::Validation),
        "{console:?}"
    );
}
