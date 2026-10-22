//! Back-channel logout delivery: a run tells every client of an ended session that registered a back-channel URI, by
//! a logout token the tenant signed for that client alone; a client that was told is done, and a client that was not
//! is kept for a later run.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_core::jose::{self, VerifyingKey};
use tessari_oauth_core::logout::LOGOUT_TOKEN_TYPE;
use tessari_oauth_daemons::{Daemon, LogoutDelivery, LogoutSender};
use tessari_oauth_infrastructure::custody::{Kek, SigningKey};
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_storage::keys::StoredKey;
use tessari_oauth_types::{
    Algorithm, ClientId, RedirectUri, ScopeSet, SessionSecret, TenantId, Timestamp, UserId,
};

use crate::{fresh_kek, storage};

const NOW: u64 = 1_800_000_000;
const ISSUER: &str = "https://id.example.com/acme";
const TOLD: &str = "https://portal.example.com/backchannel";
const REFUSING: &str = "https://kiosk.example.com/backchannel";

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn client(id: &str) -> ClientId {
    ClientId::parse(id).expect("a client id")
}

/// A sender that records what it was asked to send and answers "not told" for `REFUSING`.
#[derive(Default)]
struct Recorder {
    sent: Mutex<Vec<(String, String)>>,
}

impl LogoutSender for Recorder {
    fn send<'a>(
        &'a self,
        uri: &'a str,
        logout_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        // A short synchronous section; the guard is dropped before the future is returned.
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((uri.to_owned(), logout_token.to_owned()));
        Box::pin(async move { uri != REFUSING })
    }
}

/// `acme` provisioned with a signing key the rotation rule signs with and two clients with back-channel URIs; the
/// key's public JWK.
async fn provisioned(storage: &Storage, kek: &Kek) -> String {
    storage
        .tenants
        .provision(&acme())
        .await
        .expect("provisioned");
    let (key, pkcs8) = SigningKey::generate(Algorithm::Es256).expect("a key");
    let public_jwk = key.public_jwk().expect("a JWK");
    let stored = StoredKey {
        kid: key.kid().clone(),
        algorithm: Algorithm::Es256,
        sealed: kek
            .seal(&acme(), key.kid().as_str(), &pkcs8)
            .expect("sealed"),
        public_jwk: public_jwk.clone(),
        // Older than the key set's cache lifetime, so the rotation rule signs with it.
        created_at: Timestamp::from_unix_secs(NOW - 4_000),
        compromised: false,
    };
    storage.keys.add(&acme(), &stored).await.expect("added");
    for (name, uri) in [("portal", TOLD), ("kiosk", REFUSING)] {
        let registration = NewClient {
            client_id: client(name),
            redirect_uris: vec![RedirectUri::parse("https://app.example.com/cb").expect("a URI")],
            scope_ceiling: ScopeSet::parse("api:read").expect("scopes"),
            resources: BTreeSet::new(),
            auth_method: AuthMethod::None,
            grant_types: vec![GrantType::AuthorizationCode],
            jwks: Vec::new(),
            dpop_bound_access_tokens: false,
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: Some(RedirectUri::parse(uri).expect("a URI")),
        };
        storage
            .clients
            .register(&acme(), &registration, Timestamp::from_unix_secs(NOW))
            .await
            .expect("registered");
    }
    public_jwk
}

/// End a session of `user` that signed both clients in; its public id.
async fn ended(storage: &Storage, user: &UserId) -> String {
    let secret = SessionSecret::from_secret("cookie-1");
    let at = Timestamp::from_unix_secs(NOW);
    storage
        .sessions
        .create(&acme(), &secret, user, &[Method::Password], at)
        .await
        .expect("opened");
    let sid = storage
        .sessions
        .find(&acme(), &secret, at)
        .await
        .expect("answered")
        .expect("a live session")
        .sid;
    for name in ["portal", "kiosk"] {
        storage
            .sessions
            .record_client(&acme(), user, &sid, &client(name))
            .await
            .expect("recorded");
    }
    storage.sessions.end(&acme(), &secret).await.expect("ended");
    sid
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn each_client_is_told_by_its_own_token_and_an_untold_one_is_kept() {
    let storage = storage();
    let kek = fresh_kek();
    let published = provisioned(&storage, &kek).await;
    let user = UserId::parse("user-1").expect("a user id");
    let sid = ended(&storage, &user).await;
    let sender = Arc::new(Recorder::default());
    let daemon = LogoutDelivery {
        logouts: Arc::clone(&storage.logouts),
        clients: Arc::clone(&storage.clients),
        subjects: Arc::clone(&storage.subjects),
        keys: Arc::clone(&storage.keys),
        kek: Arc::clone(&kek),
        tenants: vec![(acme(), ISSUER.to_owned())],
        sender: Arc::clone(&sender) as Arc<dyn LogoutSender>,
        clock: Arc::new(|| Timestamp::from_unix_secs(NOW)),
        interval: Duration::from_secs(5),
        timeout: Duration::from_secs(30),
    };
    let report = daemon.run_once().await.expect("a run");
    assert_eq!(
        report.message,
        "tenants=1 sessions=1 told=1 untold=1 finished=0 retried=1"
    );
    let sent = sender
        .sent
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let uris: BTreeSet<&str> = sent.iter().map(|(uri, _)| uri.as_str()).collect();
    assert_eq!(uris, BTreeSet::from([TOLD, REFUSING]), "each client once");
    assert_eq!(sent.len(), 2);
    let key = VerifyingKey::from_jwk(&published, Algorithm::Es256).expect("a public key");
    for (uri, token) in &sent {
        let verified = jose::verify(token, Algorithm::Es256, std::slice::from_ref(&key))
            .expect("signed by the published key");
        assert_eq!(verified.typ.as_deref(), Some(LOGOUT_TOKEN_TYPE));
        let claims: serde_json::Value =
            serde_json::from_slice(&verified.payload).expect("a claims object");
        let name = if uri == TOLD { "portal" } else { "kiosk" };
        let subject = storage
            .subjects
            .pairwise(
                &acme(),
                &kek,
                &client(name),
                &user,
                Timestamp::from_unix_secs(NOW),
            )
            .await
            .expect("a subject");
        assert_eq!(claims["aud"], name);
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["sid"], sid.as_str());
        assert_eq!(claims["sub"], subject.as_str());
    }
    // The told client is done; the refusing one is kept and released to a later run, not due yet.
    assert!(
        storage
            .logouts
            .claim(&acme(), 10)
            .await
            .expect("claimed")
            .is_empty()
    );
}
