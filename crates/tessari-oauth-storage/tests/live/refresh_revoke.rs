//! A client revokes a refresh token (RFC 7009): the token's whole family ends, once and for good, and another
//! client's token, or one this tenant never issued, changes nothing.

use std::collections::BTreeSet;

use tessari_oauth_storage::refresh::{RefreshGrant, Revocation, Rotation, RotationRefusal};
use tessari_oauth_types::{
    ClientId, RefreshToken, Resource, ScopeSet, TenantId, Timestamp, UserId,
};

use crate::fresh;

const START: u64 = 1_800_000_000;

fn tenant() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn client(id: &str) -> ClientId {
    ClientId::parse(id).expect("a client id")
}

fn grant() -> RefreshGrant {
    RefreshGrant {
        tenant: tenant(),
        user: UserId::parse("user-7").expect("a user id"),
        client_id: client("portal"),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        resources: BTreeSet::from([
            Resource::parse("https://api.example.com/").expect("a resource")
        ]),
        bound_to: None,
    }
}

fn token(name: &str) -> RefreshToken {
    RefreshToken::from_secret(format!("refresh-secret-{name}"))
}

fn at(offset: u64) -> Timestamp {
    Timestamp::from_unix_secs(START.checked_add(offset).expect("a time within range"))
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn revoking_a_token_ends_its_whole_family() {
    let storage = fresh(&tenant(), 2).await;
    let refresh = &storage.refresh;
    refresh
        .start(&token("a"), &grant(), "family-r", at(0))
        .await
        .expect("started");
    let rotated = refresh
        .rotate(
            &tenant(),
            &token("a"),
            &token("b"),
            &client("portal"),
            at(1),
        )
        .await
        .expect("answered");
    assert!(matches!(rotated, Rotation::Rotated(_)), "{rotated:?}");

    // The spent predecessor names the family as well as the live successor does.
    assert_eq!(
        refresh
            .revoke_token(&tenant(), &token("a"), &client("portal"), at(2))
            .await
            .expect("answered"),
        Revocation::Revoked
    );
    assert_eq!(
        refresh
            .rotate(
                &tenant(),
                &token("b"),
                &token("c"),
                &client("portal"),
                at(3)
            )
            .await
            .expect("answered"),
        Rotation::Refused(RotationRefusal::FamilyRevoked)
    );
    assert_eq!(
        refresh
            .revoke_token(&tenant(), &token("b"), &client("portal"), at(4))
            .await
            .expect("answered"),
        Revocation::Revoked,
        "revoking again changes nothing and still answers revoked"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn another_clients_token_or_an_unknown_one_changes_nothing() {
    let storage = fresh(&tenant(), 2).await;
    let refresh = &storage.refresh;
    refresh
        .start(&token("x"), &grant(), "family-x", at(0))
        .await
        .expect("started");
    assert_eq!(
        refresh
            .revoke_token(&tenant(), &token("x"), &client("studio"), at(1))
            .await
            .expect("answered"),
        Revocation::OtherClient
    );
    assert_eq!(
        refresh
            .revoke_token(&tenant(), &token("never"), &client("portal"), at(1))
            .await
            .expect("answered"),
        Revocation::Unknown
    );
    let still = refresh
        .rotate(
            &tenant(),
            &token("x"),
            &token("y"),
            &client("portal"),
            at(2),
        )
        .await
        .expect("answered");
    assert!(matches!(still, Rotation::Rotated(_)), "{still:?}");
}
