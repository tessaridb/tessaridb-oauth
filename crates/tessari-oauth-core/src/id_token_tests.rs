use serde_json::{Value, json};
use tessari_oauth_types::{Algorithm, ClientId, Timestamp};

use super::{Authenticated, claims};

const ISSUED_AT: u64 = 1_800_000_000;
const TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl";

fn client() -> ClientId {
    ClientId::parse("portal").expect("a client id")
}

fn written(authenticated: &Authenticated<'_>, access_token: Option<(&str, Algorithm)>) -> Value {
    let claims = claims(
        authenticated,
        Timestamp::from_unix_secs(ISSUED_AT),
        access_token,
    )
    .expect("claims");
    serde_json::to_value(claims).expect("serialisable")
}

#[test]
fn an_id_token_states_the_authentication_and_nothing_else() {
    let client = client();
    let amr = ["pwd", "otp"];
    let authenticated = Authenticated {
        issuer: "https://id.example.com/acme",
        subject: "pairwise-sub",
        client_id: &client,
        auth_time: Timestamp::from_unix_secs(ISSUED_AT - 30),
        nonce: Some("n-0S6_WzA2Mj"),
        acr: Some("urn:example:mfa"),
        amr: &amr,
        session_id: "session-1",
    };
    assert_eq!(
        written(&authenticated, Some((TOKEN, Algorithm::Es256))),
        json!({
            "iss": "https://id.example.com/acme",
            "sub": "pairwise-sub",
            "aud": "portal",
            "exp": ISSUED_AT + 300,
            "iat": ISSUED_AT,
            "auth_time": ISSUED_AT - 30,
            "nonce": "n-0S6_WzA2Mj",
            "acr": "urn:example:mfa",
            "amr": ["pwd", "otp"],
            "sid": "session-1",
            // Left half of SHA-256 over the ASCII token, base64url — computed outside this code.
            "at_hash": "OK3EEs9JO3VGVujvOBpDjQ",
        })
    );
}

#[test]
fn what_was_not_requested_or_not_verified_is_absent() {
    let client = client();
    let authenticated = Authenticated {
        issuer: "https://id.example.com/acme",
        subject: "pairwise-sub",
        client_id: &client,
        auth_time: Timestamp::from_unix_secs(ISSUED_AT),
        nonce: None,
        acr: None,
        amr: &[],
        session_id: "session-1",
    };
    let document = written(&authenticated, None);
    for absent in ["nonce", "acr", "amr", "at_hash", "azp"] {
        assert!(document.get(absent).is_none(), "{absent}: {document}");
    }
}

#[test]
fn an_at_hash_for_an_algorithm_without_a_known_digest_is_refused() {
    let client = client();
    let authenticated = Authenticated {
        issuer: "https://id.example.com/acme",
        subject: "pairwise-sub",
        client_id: &client,
        auth_time: Timestamp::from_unix_secs(ISSUED_AT),
        nonce: None,
        acr: None,
        amr: &[],
        session_id: "session-1",
    };
    assert!(
        claims(
            &authenticated,
            Timestamp::from_unix_secs(ISSUED_AT),
            Some((TOKEN, Algorithm::EdDsa))
        )
        .is_err()
    );
}

#[test]
fn the_claim_names_are_every_claim_a_full_id_token_writes() {
    let client = client();
    let amr = ["pwd"];
    let authenticated = Authenticated {
        issuer: "https://id.example.com/acme",
        subject: "pairwise-sub",
        client_id: &client,
        auth_time: Timestamp::from_unix_secs(ISSUED_AT),
        nonce: Some("n"),
        acr: Some("urn:example:mfa"),
        amr: &amr,
        session_id: "session-1",
    };
    let written = written(&authenticated, Some((TOKEN, Algorithm::Es256)));
    let mut keys: Vec<&str> = written
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    let mut names = super::CLAIM_NAMES.to_vec();
    keys.sort_unstable();
    names.sort_unstable();
    assert_eq!(keys, names);
}
