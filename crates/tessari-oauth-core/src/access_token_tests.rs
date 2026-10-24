use tessari_oauth_types::{ClientId, KeyThumbprint, Resource, ScopeSet, Timestamp};

use super::{Grant, TYPE, claims};
use crate::fixtures::ACME_ISSUER;

fn grant<'a>(audience: &'a Resource, client_id: &'a ClientId, scopes: &'a ScopeSet) -> Grant<'a> {
    Grant {
        issuer: ACME_ISSUER,
        audience,
        subject: "pw-9f3c",
        client_id,
        scopes,
        bound_to: None,
    }
}

#[test]
fn the_claims_are_the_access_token_profile_and_nothing_else() {
    let audience = Resource::parse("https://api.example.com/orders").expect("a resource");
    let client_id = ClientId::parse("svc-1").expect("a client id");
    let scopes = ScopeSet::parse("orders:write orders:read").expect("scopes");
    let encoded = serde_json::to_string(&claims(
        &grant(&audience, &client_id, &scopes),
        "jti-1",
        Timestamp::from_unix_secs(1_800_000_000),
    ))
    .expect("claims encode");
    assert_eq!(
        encoded,
        concat!(
            r#"{"iss":"https://id.example.com/acme","exp":1800000300,"aud":"https://api.example.com/orders","#,
            r#""sub":"pw-9f3c","client_id":"svc-1","iat":1800000000,"jti":"jti-1","#,
            r#""scope":"orders:read orders:write"}"#
        )
    );
}

#[test]
fn the_token_is_typed_as_an_access_token() {
    assert_eq!(TYPE, "at+jwt");
}

#[test]
fn a_token_bound_to_a_proof_key_names_its_thumbprint_and_nothing_more() {
    let audience = Resource::parse("https://api.example.com/orders").expect("a resource");
    let client_id = ClientId::parse("svc-1").expect("a client id");
    let scopes = ScopeSet::parse("orders:read").expect("scopes");
    let key =
        KeyThumbprint::parse("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I").expect("a thumbprint");
    let bound = Grant {
        bound_to: Some(&key),
        ..grant(&audience, &client_id, &scopes)
    };
    let encoded = serde_json::to_string(&claims(
        &bound,
        "jti-2",
        Timestamp::from_unix_secs(1_800_000_000),
    ))
    .expect("claims encode");
    assert_eq!(
        encoded,
        concat!(
            r#"{"iss":"https://id.example.com/acme","exp":1800000300,"aud":"https://api.example.com/orders","#,
            r#""sub":"pw-9f3c","client_id":"svc-1","iat":1800000000,"jti":"jti-2","scope":"orders:read","#,
            r#""cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}}"#
        )
    );
}
