//! The account portal's session list: a signed-in user sees their own live sessions at this issuer, by public id and
//! never by cookie, ends any one of them, or ends them all together with every refresh family they hold ("log out
//! everywhere"), each ending recorded; nobody else's session is shown or ended.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_types::{SessionSecret, Timestamp, UserId};

use crate::account_grants::{call, family};
use crate::authorize_resume::signed_in;
use crate::token_fixture::{NOW, Server, server, tenant};

/// Open another session for `user` under the cookie value `value`, signed in `ago` seconds before now.
async fn opened(server: &Server, user: &UserId, value: &str, ago: u64) {
    server
        .storage
        .sessions
        .create(
            &tenant("acme"),
            &SessionSecret::from_secret(value.to_owned()),
            user,
            &[Method::Password, Method::Totp],
            Timestamp::from_unix_secs(NOW.checked_sub(ago).expect("an instant")),
        )
        .await
        .expect("opened");
}

/// Whether the session under the cookie value `value` is still found.
async fn alive(server: &Server, value: &str) -> bool {
    server
        .storage
        .sessions
        .find(
            &tenant("acme"),
            &SessionSecret::from_secret(value.to_owned()),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .is_some()
}

/// The sessions the account API lists for the holder of `session`.
async fn listed(server: &Server, session: &str) -> Vec<Value> {
    let answered = call(server, "GET", "sessions", Some(session), None).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    answered.body["sessions"]
        .as_array()
        .expect("a list")
        .clone()
}

/// The `(reason, families)` of every `SessionsEnded` record for `user`.
async fn endings(server: &Server, user: &UserId) -> Vec<(Option<String>, Option<u64>)> {
    server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .map(|record| record.event)
        .filter(|event| event.kind == AuditKind::SessionsEnded && event.user.as_ref() == Some(user))
        .map(|event| (event.reason, event.families))
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_user_sees_their_own_live_sessions_by_public_id_only() {
    let server = server(2).await;
    let (_, session, user) = signed_in(&server, "turing@example.com").await;
    let (_, _, other) = signed_in(&server, "church@example.com").await;
    opened(&server, &user, "a-phone-session", 600).await;
    opened(&server, &user, "a-session-from-last-week", 8 * 24 * 3_600).await;
    opened(&server, &other, "another-users-session", 60).await;
    let sessions = listed(&server, &session).await;
    assert_eq!(
        sessions.len(),
        2,
        "the live two, not the lapsed one nor another user's: {sessions:?}"
    );
    for entry in &sessions {
        let keys: BTreeSet<&str> = entry
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from(["sid", "signed_in_at", "last_seen_at", "methods", "current"]),
            "a public id and facts, never the cookie or the record's id"
        );
        assert!(!entry.to_string().contains("a-phone-session"));
    }
    let current: Vec<&Value> = sessions
        .iter()
        .filter(|entry| entry["current"] == true)
        .collect();
    assert_eq!(current.len(), 1, "the session asking is marked");
    let phone = sessions
        .iter()
        .find(|entry| entry["current"] == false)
        .expect("the other session");
    assert_eq!(phone["signed_in_at"], NOW - 600);
    assert_eq!(phone["methods"], json!(["pwd", "totp"]));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_user_ends_one_of_their_sessions_and_never_another_users() {
    let server = server(2).await;
    let (_, session, user) = signed_in(&server, "hamming@example.com").await;
    let (_, other_session, other) = signed_in(&server, "shannon@example.com").await;
    opened(&server, &user, "a-tablet-session", 600).await;
    let tablet = listed(&server, &session)
        .await
        .into_iter()
        .find(|entry| entry["current"] == false)
        .expect("the tablet session");
    let theirs = listed(&server, &other_session).await;
    let their_sid = theirs[0]["sid"].clone();
    let refused = call(
        &server,
        "POST",
        "sessions/end",
        Some(&session),
        Some(json!({ "sid": their_sid })),
    )
    .await;
    assert_eq!(
        refused.body,
        json!({ "ended": false }),
        "another user's session is not ours to end"
    );
    assert!(alive(&server, &other_session).await);
    let ended = call(
        &server,
        "POST",
        "sessions/end",
        Some(&session),
        Some(json!({ "sid": tablet["sid"] })),
    )
    .await;
    assert_eq!(ended.status, StatusCode::OK, "{}", ended.body);
    assert_eq!(ended.body, json!({ "ended": true }));
    assert!(
        !alive(&server, "a-tablet-session").await,
        "the tablet is signed out"
    );
    assert!(alive(&server, &session).await, "the session asking is not");
    assert_eq!(
        endings(&server, &user).await,
        [(Some("one".to_owned()), None)]
    );
    assert!(endings(&server, &other).await.is_empty());
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn signing_out_everywhere_ends_every_session_and_family_of_the_user_alone() {
    let server = server(2).await;
    let (_, session, user) = signed_in(&server, "dijkstra@example.com").await;
    let (_, other_session, _) = signed_in(&server, "hoare@example.com").await;
    opened(&server, &user, "a-laptop-session", 600).await;
    family(&server, &user, "refresh-of-the-laptop").await;
    let ended = call(
        &server,
        "POST",
        "sessions/end-all",
        Some(&session),
        Some(json!({})),
    )
    .await;
    assert_eq!(ended.status, StatusCode::OK, "{}", ended.body);
    assert_eq!(
        ended.body,
        json!({ "sessions": 2, "families": 1, "access_tokens_end_by": NOW + 300 })
    );
    assert!(!alive(&server, &session).await);
    assert!(!alive(&server, "a-laptop-session").await);
    assert!(
        alive(&server, &other_session).await,
        "another user stays signed in"
    );
    let after = call(&server, "GET", "sessions", Some(&session), None).await;
    assert_eq!(
        after.status,
        StatusCode::UNAUTHORIZED,
        "the asking session ended too"
    );
    assert_eq!(
        endings(&server, &user).await,
        [(Some("everywhere".to_owned()), Some(1))]
    );
}
