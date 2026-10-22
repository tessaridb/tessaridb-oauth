//! Operator roles: a grant is held until it is revoked or expires, every grant and revoke is on the audit trail, and
//! the two grants nobody may make, to oneself and of a role above the company's ceiling, write nothing.

use tessari_oauth_storage::Storage;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::operators::{Granted, OperatorGrant, OperatorRole};
use tessari_oauth_types::{TenantId, Timestamp, UserId};

use crate::fresh;

const NOW: u64 = 1_800_000_000;

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn system() -> TenantId {
    TenantId::parse("system").expect("a tenant id")
}

fn user(raw: &str) -> UserId {
    UserId::parse(raw).expect("a user id")
}

fn grant(holder: &str, role: OperatorRole, by: &str, expires_at: Option<u64>) -> OperatorGrant {
    OperatorGrant {
        user: user(holder),
        role,
        granted_by: by.to_owned(),
        granted_at: Timestamp::from_unix_secs(NOW),
        reason: format!("{} for {holder}", role.name()),
        expires_at: expires_at.map(Timestamp::from_unix_secs),
    }
}

async fn roles(storage: &Storage, tenant: &TenantId, holder: &str, at: u64) -> Vec<OperatorRole> {
    let mut roles: Vec<OperatorRole> = storage
        .operators
        .grants(tenant, &user(holder), Timestamp::from_unix_secs(at))
        .await
        .expect("an answer")
        .into_iter()
        .map(|grant| grant.role)
        .collect();
    roles.sort_by_key(|role| role.name());
    roles
}

async fn trail(storage: &Storage, tenant: &TenantId) -> Vec<AuditEvent> {
    storage
        .audit
        .read_after(tenant, 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .map(|record| record.event)
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_grant_is_held_with_its_record_until_it_is_revoked() {
    let storage = fresh(&acme(), 2).await;
    let given = grant("user-1", OperatorRole::Users, "operator-9", None);
    assert_eq!(
        storage
            .operators
            .grant(&acme(), &given)
            .await
            .expect("an answer"),
        Granted::Granted
    );
    let held = storage
        .operators
        .grants(&acme(), &user("user-1"), Timestamp::from_unix_secs(NOW))
        .await
        .expect("an answer");
    assert_eq!(held, vec![given]);
    assert!(
        storage
            .operators
            .revoke(
                &acme(),
                &user("user-1"),
                OperatorRole::Users,
                "operator-9",
                "moved team",
                Timestamp::from_unix_secs(NOW + 1),
            )
            .await
            .expect("an answer"),
        "the grant stood"
    );
    assert!(roles(&storage, &acme(), "user-1", NOW + 1).await.is_empty());
    assert!(
        !storage
            .operators
            .revoke(
                &acme(),
                &user("user-1"),
                OperatorRole::Users,
                "operator-9",
                "again",
                Timestamp::from_unix_secs(NOW + 2),
            )
            .await
            .expect("an answer"),
        "nothing left to revoke"
    );
    assert_eq!(
        trail(&storage, &acme()).await,
        vec![
            AuditEvent {
                user: Some(user("user-1")),
                actor: Some("operator-9".to_owned()),
                role: Some(OperatorRole::Users),
                reason: Some("users for user-1".to_owned()),
                ..AuditEvent::of(AuditKind::OperatorGranted)
            },
            AuditEvent {
                user: Some(user("user-1")),
                actor: Some("operator-9".to_owned()),
                role: Some(OperatorRole::Users),
                reason: Some("moved team".to_owned()),
                ..AuditEvent::of(AuditKind::OperatorRevoked)
            },
        ],
        "a revoke that removed nothing is not recorded as one"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_grant_stops_counting_at_its_expiry_and_a_regrant_replaces_it() {
    let storage = fresh(&acme(), 2).await;
    for given in [
        grant("user-1", OperatorRole::Audit, "operator-9", Some(NOW + 60)),
        grant("user-1", OperatorRole::Clients, "operator-9", None),
    ] {
        storage
            .operators
            .grant(&acme(), &given)
            .await
            .expect("granted");
    }
    assert_eq!(
        roles(&storage, &acme(), "user-1", NOW + 59).await,
        [OperatorRole::Audit, OperatorRole::Clients]
    );
    assert_eq!(
        roles(&storage, &acme(), "user-1", NOW + 60).await,
        [OperatorRole::Clients],
        "expired at its instant"
    );
    storage
        .operators
        .grant(
            &acme(),
            &grant("user-1", OperatorRole::Audit, "operator-9", Some(NOW + 600)),
        )
        .await
        .expect("granted again");
    assert_eq!(
        roles(&storage, &acme(), "user-1", NOW + 60).await,
        [OperatorRole::Audit, OperatorRole::Clients],
        "the later expiry replaced the earlier one"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn nobody_grants_a_role_to_themselves() {
    let storage = fresh(&acme(), 2).await;
    let own = grant("user-1", OperatorRole::Users, "user-1", None);
    assert_eq!(
        storage
            .operators
            .grant(&acme(), &own)
            .await
            .expect("an answer"),
        Granted::SelfGrant
    );
    assert!(roles(&storage, &acme(), "user-1", NOW).await.is_empty());
    assert!(
        trail(&storage, &acme()).await.is_empty(),
        "nothing was granted"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_companies_role_is_held_only_in_the_system_company() {
    let storage = fresh(&acme(), 2).await;
    storage
        .tenants
        .provision(&system())
        .await
        .expect("provisioned");
    let platform = grant("user-1", OperatorRole::Companies, "break-glass", None);
    assert_eq!(
        storage
            .operators
            .grant(&acme(), &platform)
            .await
            .expect("an answer"),
        Granted::AboveCeiling
    );
    assert!(roles(&storage, &acme(), "user-1", NOW).await.is_empty());
    assert_eq!(
        storage
            .operators
            .grant(&system(), &platform)
            .await
            .expect("an answer"),
        Granted::Granted
    );
    assert_eq!(
        roles(&storage, &system(), "user-1", NOW).await,
        [OperatorRole::Companies]
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_page_holds_only_current_grants_of_the_roles_asked_for_in_record_order() {
    let storage = fresh(&acme(), 2).await;
    for (holder, role, expires_at) in [
        ("user-a", OperatorRole::Users, None),
        ("user-a", OperatorRole::Audit, None),
        ("user-b", OperatorRole::Users, Some(NOW + 10)),
        ("user-c", OperatorRole::Policy, None),
        ("user-d", OperatorRole::Users, Some(NOW + 3600)),
    ] {
        let granted = storage
            .operators
            .grant(&acme(), &grant(holder, role, "operator-1", expires_at))
            .await
            .expect("granted");
        assert_eq!(granted, Granted::Granted);
    }
    let later = Timestamp::from_unix_secs(NOW + 20);
    let asked = [OperatorRole::Users, OperatorRole::Audit];
    let named = |page: &[OperatorGrant]| -> Vec<(String, &'static str)> {
        page.iter()
            .map(|grant| (grant.user.as_str().to_owned(), grant.role.name()))
            .collect()
    };
    let first = storage
        .operators
        .page(&acme(), &asked, None, 2, later)
        .await
        .expect("a page");
    assert_eq!(
        named(&first),
        [
            ("user-a".to_owned(), "audit"),
            ("user-a".to_owned(), "users")
        ]
    );
    assert_eq!(first[1].reason, "users for user-a");
    let last = &first[1];
    let second = storage
        .operators
        .page(&acme(), &asked, Some((&last.user, last.role)), 2, later)
        .await
        .expect("a page");
    assert_eq!(named(&second), [("user-d".to_owned(), "users")]);
    assert_eq!(
        second[0].expires_at,
        Some(Timestamp::from_unix_secs(NOW + 3600))
    );
    let policy_only = storage
        .operators
        .page(&acme(), &[OperatorRole::Policy], None, 100, later)
        .await
        .expect("a page");
    assert_eq!(named(&policy_only), [("user-c".to_owned(), "policy")]);
}
