//! The grant a refresh token carries, read before anything is rotated: the family's grant for any token of it, and
//! nothing for a token this tenant never issued.

use std::collections::BTreeSet;

use tessari_oauth_storage::refresh::{RefreshGrant, Rotation};
use tessari_oauth_types::{
    ClientId, RefreshToken, Resource, ScopeSet, TenantId, Timestamp, UserId,
};

use crate::fresh;

const START: u64 = 1_800_000_000;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn grant() -> RefreshGrant {
    RefreshGrant {
        tenant: tenant("acme"),
        user: UserId::parse("user-7").expect("a user id"),
        client_id: ClientId::parse("portal").expect("a client id"),
        scopes: ScopeSet::parse("api:read api:write").expect("scopes"),
        resources: BTreeSet::from([
            Resource::parse("https://api.example.com/").expect("a resource"),
            Resource::parse("https://files.example.com/").expect("a resource"),
        ]),
    }
}

fn token(name: &str) -> RefreshToken {
    RefreshToken::from_secret(format!("refresh-secret-{name}"))
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_token_of_a_family_reads_as_its_grant_and_an_unknown_one_as_none() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    storage
        .tenants
        .provision(&tenant("initech"))
        .await
        .expect("provisioned");
    let refresh = &storage.refresh;
    refresh
        .start(
            &token("a"),
            &grant(),
            "family-1",
            Timestamp::from_unix_secs(START),
        )
        .await
        .expect("started");
    assert_eq!(
        refresh.grant(&acme, &token("a")).await.expect("read"),
        Some(grant())
    );

    let rotation = refresh
        .rotate(
            &acme,
            &token("a"),
            &token("b"),
            &grant().client_id,
            Timestamp::from_unix_secs(START + 1),
        )
        .await
        .expect("answered");
    assert_eq!(rotation, Rotation::Rotated(grant()));
    // The successor carries the same grant; reading never spends or judges a token.
    assert_eq!(
        refresh.grant(&acme, &token("b")).await.expect("read"),
        Some(grant())
    );
    assert_eq!(
        refresh.grant(&acme, &token("a")).await.expect("read"),
        Some(grant())
    );

    assert_eq!(
        refresh.grant(&acme, &token("never")).await.expect("read"),
        None
    );
    assert_eq!(
        refresh
            .grant(&tenant("initech"), &token("b"))
            .await
            .expect("read"),
        None,
        "another tenant's token is unknown here"
    );
}
