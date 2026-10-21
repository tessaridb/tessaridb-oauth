use tessari_oauth_types::{ClientId, Resource, ScopeSet, Timestamp};

use super::{Grant, TYPE, claims};
use crate::fixtures::ACME_ISSUER;

fn grant<'a>(audience: &'a Resource, client_id: &'a ClientId, scopes: &'a ScopeSet) -> Grant<'a> {
    Grant {
        issuer: ACME_ISSUER,
        audience,
        subject: "pw-9f3c",
        client_id,
        scopes,
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
