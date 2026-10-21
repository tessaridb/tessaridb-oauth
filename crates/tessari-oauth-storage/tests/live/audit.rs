//! The audit trail: every message lands in commit order with what it said, carries no secret, and stays as written.

use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{ClientId, KeyThumbprint, ScopeSet, TenantId, Timestamp, UserId};

use crate::fresh;

fn tenant() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn messages_are_read_back_in_order_as_they_were_recorded() {
    let storage = fresh(&tenant(), 2).await;
    let issued = AuditEvent {
        client_id: Some(ClientId::parse("portal").expect("a client id")),
        user: Some(UserId::parse("user-7").expect("a user id")),
        subject: Some("pairwise-subject".to_owned()),
        scopes: Some(ScopeSet::parse("api:read api:write").expect("scopes")),
        audience: Some("https://api.example.com/".to_owned()),
        jti: Some("jti-1".to_owned()),
        auth_method: Some("none".to_owned()),
        bound_to: Some(
            KeyThumbprint::parse("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_owned())
                .expect("a thumbprint"),
        ),
        ..AuditEvent::of(AuditKind::IssuedCode)
    };
    let refused = AuditEvent {
        client_id: Some(ClientId::parse("kiosk").expect("a client id")),
        reason: Some("CodeUnknown".to_owned()),
        ..AuditEvent::of(AuditKind::Refused)
    };
    let cascade = AuditEvent {
        user: Some(UserId::parse("user-7").expect("a user id")),
        reason: Some("password_changed".to_owned()),
        families: Some(3),
        ..AuditEvent::of(AuditKind::Cascade)
    };
    for (event, at) in [(&issued, 10), (&refused, 11), (&cascade, 12)] {
        storage
            .audit
            .record(&tenant(), event, Timestamp::from_unix_secs(at))
            .await
            .expect("recorded");
    }
    let trail = storage
        .audit
        .read_after(&tenant(), 0, 10)
        .await
        .expect("read");
    let read: Vec<_> = trail
        .iter()
        .map(|record| (record.position, record.at.unix_secs(), record.event.clone()))
        .collect();
    assert_eq!(
        read,
        vec![(1, 10, issued), (2, 11, refused), (3, 12, cascade.clone())]
    );
    let after = storage
        .audit
        .read_after(&tenant(), 2, 10)
        .await
        .expect("read");
    assert_eq!(after.len(), 1, "only the third comes after the second");
    assert_eq!(after[0].event, cascade);
}
