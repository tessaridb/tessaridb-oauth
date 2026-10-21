//! The token endpoint's fixtures: a live store serving two tenants with a published key and two public clients each,
//! codes issued straight into it, and requests posted through the router as the listener posts them.

use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroU64;
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use tessari_oauth_api::{PublicState, public_router};
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_core::codes::IssuedCode;
use tessari_oauth_infrastructure::custody::{Kek, SigningKey};
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_storage::keys::StoredKey;
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_test_support::{fresh_kek, fresh_storage, plain_node};
use tessari_oauth_types::{
    Algorithm, AuthorizationCode, Challenge, ClientId, RedirectUri, Resource, ScopeSet, TenantId,
    Timestamp, UserId,
};
use tower::ServiceExt;

use crate::routes::{Answer, answer, header, protected};

pub(crate) const NOW: u64 = 1_800_000_000;
pub(crate) const VERIFIER: &str = "verifier-0123456789-0123456789-0123456789-abcdef";
pub(crate) const REDIRECT: &str = "https://app.example.com/callback";
pub(crate) const API: &str = "https://api.example.com/";
pub(crate) const USER: &str = "user-7";

pub(crate) fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

pub(crate) fn issuer(tenant: &str) -> String {
    format!("https://id.example.com/{tenant}")
}

/// Storage on the live node with `acme` and `initech` served, each holding a published signing key and two public
/// clients: `portal`, registered for refresh tokens, and `kiosk`, which is not.
pub(crate) struct Server {
    pub(crate) storage: Storage,
    kek: Arc<Kek>,
    /// `acme`'s published signing key.
    pub(crate) published: String,
}

pub(crate) async fn server(connections: usize) -> Server {
    let storage = fresh_storage(plain_node().expect("the plain node is named"), connections)
        .expect("a configuration the pool accepts");
    storage.throttle.prepare().await.expect("counters prepared");
    let kek = Arc::new(fresh_kek().expect("a key-encryption key"));
    let mut published = String::new();
    for name in ["acme", "initech"] {
        let id = tenant(name);
        storage.tenants.provision(&id).await.expect("provisioned");
        let (key, pkcs8) = SigningKey::generate(Algorithm::Es256).expect("a key");
        let public_jwk = key.public_jwk().expect("a JWK");
        // Older than the key set's cache lifetime, so the rotation rule signs with it.
        let stored = StoredKey {
            kid: key.kid().clone(),
            algorithm: Algorithm::Es256,
            sealed: kek.seal(&id, key.kid().as_str(), &pkcs8).expect("sealed"),
            public_jwk: public_jwk.clone(),
            created_at: Timestamp::from_unix_secs(NOW - 4_000),
            compromised: false,
        };
        storage.keys.add(&id, &stored).await.expect("added");
        if name == "acme" {
            published = public_jwk;
        }
        for (client, grants) in [
            (
                "portal",
                vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            ),
            ("kiosk", vec![GrantType::AuthorizationCode]),
        ] {
            let registration = NewClient {
                client_id: ClientId::parse(client).expect("a client id"),
                redirect_uris: vec![RedirectUri::parse(REDIRECT).expect("a redirect URI")],
                scope_ceiling: ScopeSet::parse("api:read api:write").expect("scopes"),
                auth_method: AuthMethod::None,
                grant_types: grants,
                jwks: Vec::new(),
            };
            let at = Timestamp::from_unix_secs(NOW - 100);
            storage
                .clients
                .register(&id, &registration, at)
                .await
                .expect("registered");
        }
    }
    Server {
        storage,
        kek,
        published,
    }
}

pub(crate) fn plenty() -> Limit {
    Limit {
        requests: NonZeroU64::new(1_000).expect("non-zero"),
        window_secs: NonZeroU64::new(60).expect("non-zero"),
    }
}

/// The public state over `server`, counting token requests under `token_limit`.
pub(crate) fn state(server: &Server, token_limit: Limit) -> PublicState {
    let storage = &server.storage;
    PublicState {
        keys: Arc::clone(&storage.keys),
        clients: Arc::clone(&storage.clients),
        codes: Arc::clone(&storage.codes),
        refresh: Arc::clone(&storage.refresh),
        replay: Arc::clone(&storage.replay),
        subjects: Arc::clone(&storage.subjects),
        kek: Arc::clone(&server.kek),
        throttle: Arc::clone(&storage.throttle),
        read_limit: plenty(),
        token_limit,
        issuers: Arc::new(HashMap::from(
            ["acme", "initech"].map(|name| (tenant(name), issuer(name))),
        )),
        clock: Arc::new(|| Timestamp::from_unix_secs(NOW)),
    }
}

/// Issue the code `secret` in `tenant` to `client` for `user-7`, at `api:read` on the API, expiring at `expires_at`.
pub(crate) async fn issue(
    server: &Server,
    tenant_name: &str,
    client: &str,
    secret: &str,
    expires_at: u64,
) {
    let issued = IssuedCode {
        tenant: tenant(tenant_name),
        client_id: ClientId::parse(client).expect("a client id"),
        user: UserId::parse(USER).expect("a user id"),
        redirect_uri: REDIRECT.to_owned(),
        challenge: Challenge::of(VERIFIER).expect("a challenge"),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
        expires_at: Timestamp::from_unix_secs(expires_at),
    };
    server
        .storage
        .codes
        .issue(&AuthorizationCode::from_secret(secret), &issued)
        .await
        .expect("issued");
}

/// The parameters that redeem `code` for `client`.
pub(crate) fn redemption<'a>(client: &'a str, code: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", "authorization_code"),
        ("client_id", client),
        ("code", code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ]
}

/// POST `body` as `content_type` to `tenant`'s token endpoint, with `authorization` when given.
pub(crate) async fn post_raw(
    server: &Server,
    tenant_name: &str,
    content_type: &str,
    body: String,
    authorization: Option<&str>,
) -> Answer {
    let mut request =
        Request::post(format!("/{tenant_name}/oauth2/token")).header("content-type", content_type);
    if let Some(credentials) = authorization {
        request = request.header("authorization", credentials);
    }
    let response = public_router(state(server, plenty()))
        .oneshot(request.body(Body::from(body)).expect("a request"))
        .await
        .expect("the router answers");
    answer(response).await
}

/// POST `pairs` as a form to `tenant`'s token endpoint.
pub(crate) async fn post(server: &Server, tenant_name: &str, pairs: &[(&str, &str)]) -> Answer {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    post_raw(
        server,
        tenant_name,
        "application/x-www-form-urlencoded",
        body,
        None,
    )
    .await
}

/// The answer is never stored by a cache and carries the headers every answer carries.
pub(crate) fn uncached(answer: &Answer) {
    assert_eq!(header(answer, "cache-control"), "no-store");
    assert_eq!(header(answer, "pragma"), "no-cache");
    protected(answer);
}
