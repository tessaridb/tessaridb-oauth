//! A company's mail wording in its console, set by an operator holding `policy`: every kind read with the wording in
//! force, a company's own wording replaced only from the revision the operator read and only when it passes the
//! kind's rules, and reset to the default. Each change carries its reason and is made once per `Idempotency-Key`; the
//! trail keeps the reason and never the wording.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tessari_oauth_api::admin_router;
use tessari_oauth_core::mail_template::MailKind;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const MAIL: &str = "/admin/acme/api/mail";
const RESET: &str = "/admin/acme/api/mail/reset/reset";
const OWN: &str =
    r#"{"revision":0,"subject":"Acme: reset","text":"Open {link} to reset.","reason":"wording"}"#;

fn change(method: Method, path: &str, key: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, "__Host-tessari-admin=console-p")
        .header(header::ORIGIN, CONSOLE)
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(body.to_owned()))
        .expect("a request")
}

fn read() -> Request<Body> {
    Request::get(MAIL)
        .header(header::COOKIE, "__Host-tessari-admin=console-p")
        .body(Body::empty())
        .expect("a request")
}

async fn send(state: tessari_oauth_api::AdminState, request: Request<Body>) -> Answer {
    answer(
        admin_router(state)
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await
}

/// The row for `kind` in a read of every kind.
fn row<'a>(answer: &'a Answer, kind: &str) -> &'a serde_json::Value {
    answer.body["mail"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|row| row["kind"] == kind)
        .unwrap_or_else(|| panic!("{kind} is listed"))
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_reads_every_mail_and_sets_its_own_wording_once_from_the_revision_read() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-p",
        &[OperatorRole::Policy],
        "issuer-p",
        "console-p",
    )
    .await;
    let before = send(state.clone(), read()).await;
    assert_eq!(before.status, StatusCode::OK, "{:?}", before.body);
    assert_eq!(
        before.body["mail"].as_array().map(Vec::len),
        Some(MailKind::ALL.len())
    );
    let shipped = MailKind::Reset.built_in();
    let reset = row(&before, "reset");
    assert_eq!(reset["subject"], shipped.subject.as_str());
    assert_eq!(reset["own"], false);
    assert_eq!(reset["revision"], 0);
    assert_eq!(reset["placeholders"], serde_json::json!(["issuer", "link"]));
    assert_eq!(reset["required"], serde_json::json!(["link"]));

    let made = send(
        state.clone(),
        change(
            Method::PUT,
            "/admin/acme/api/mail/reset",
            "mail-set-key-0001",
            OWN,
        ),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    assert_eq!(made.body["own"], true);
    assert_eq!(made.body["revision"], 1);
    assert_eq!(made.body["text"], "Open {link} to reset.");
    let again = send(
        state.clone(),
        change(
            Method::PUT,
            "/admin/acme/api/mail/reset",
            "mail-set-key-0001",
            OWN,
        ),
    )
    .await;
    assert_eq!(again.body, made.body, "answered as the first was");
    let stale = send(
        state.clone(),
        change(
            Method::PUT,
            "/admin/acme/api/mail/reset",
            "mail-set-key-0002",
            OWN,
        ),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{:?}", stale.body);
    assert_eq!(stale.body["code"], "changed_meanwhile");

    let sent = server
        .storage
        .mail_templates
        .resolve(&tenant("acme"), MailKind::Reset)
        .await
        .expect("the wording");
    assert_eq!(
        sent.subject, "Acme: reset",
        "the mail goes with the company's own"
    );
    let after = send(state.clone(), read()).await;
    assert_eq!(row(&after, "reset")["revision"], 1);
    assert_eq!(row(&after, "verify")["own"], false, "other kinds untouched");

    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail");
    let sets: Vec<_> = trail
        .iter()
        .filter(|record| {
            record.event.kind == AuditKind::AdminAction
                && record.event.action.as_deref() == Some("mail.set")
        })
        .collect();
    assert_eq!(
        sets.len(),
        2,
        "the change and the stale one; the repeat is answered from the record"
    );
    assert_eq!(sets[0].event.reason.as_deref(), Some("wording"));
    assert_eq!(sets[0].event.actor.as_deref(), Some("operator-p"));
    let recorded = format!("{:?}", sets[0].event);
    assert!(!recorded.contains("Open {link}"), "no wording in the trail");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn wording_that_breaks_a_kinds_rules_is_refused_and_nothing_is_kept() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-p",
        &[OperatorRole::Policy],
        "issuer-p",
        "console-p",
    )
    .await;
    let refusals = [
        r#"{"revision":0,"subject":"Reset","text":"No link here.","reason":"r"}"#,
        r#"{"revision":0,"subject":"Reset","text":"Open {link} for {new_address}.","reason":"r"}"#,
        r#"{"revision":0,"subject":"Reset","text":"Open {link} {nonsense}.","reason":"r"}"#,
        r#"{"revision":0,"subject":"","text":"Open {link}.","reason":"r"}"#,
        r#"{"revision":0,"subject":"Re\nset","text":"Open {link}.","reason":"r"}"#,
        r#"{"revision":0,"subject":"Reset","text":"Open {link.","reason":"r"}"#,
    ];
    for (number, body) in refusals.into_iter().enumerate() {
        let refused = send(
            state.clone(),
            change(
                Method::PUT,
                "/admin/acme/api/mail/reset",
                &format!("mail-bad-key-{number:04}"),
                body,
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(refused.body["code"], "template_rejected", "{body}");
        assert!(
            refused.body["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty())
        );
    }
    let after = send(state.clone(), read()).await;
    assert_eq!(row(&after, "reset")["own"], false, "nothing kept");

    let unknown = send(
        state.clone(),
        change(
            Method::PUT,
            "/admin/acme/api/mail/welcome",
            "mail-bad-key-0100",
            OWN,
        ),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let no_reason = send(
        state,
        change(
            Method::PUT,
            "/admin/acme/api/mail/reset",
            "mail-bad-key-0101",
            r#"{"revision":0,"subject":"Reset","text":"Open {link}.","reason":" "}"#,
        ),
    )
    .await;
    assert_eq!(no_reason.status, StatusCode::BAD_REQUEST);
    assert_eq!(no_reason.body["code"], "reason_required");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_reset_sends_the_default_again_and_only_from_the_revision_read() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-p",
        &[OperatorRole::Policy],
        "issuer-p",
        "console-p",
    )
    .await;
    let none = send(
        state.clone(),
        change(
            Method::POST,
            RESET,
            "mail-reset-key-0001",
            r#"{"revision":0,"reason":"r"}"#,
        ),
    )
    .await;
    assert_eq!(none.status, StatusCode::NOT_FOUND, "{:?}", none.body);
    assert_eq!(none.body["code"], "not_found");

    let made = send(
        state.clone(),
        change(
            Method::PUT,
            "/admin/acme/api/mail/reset",
            "mail-reset-key-0002",
            OWN,
        ),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    let stale = send(
        state.clone(),
        change(
            Method::POST,
            RESET,
            "mail-reset-key-0003",
            r#"{"revision":7,"reason":"r"}"#,
        ),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{:?}", stale.body);
    assert_eq!(stale.body["code"], "changed_meanwhile");

    let reset = send(
        state.clone(),
        change(
            Method::POST,
            RESET,
            "mail-reset-key-0004",
            r#"{"revision":1,"reason":"back"}"#,
        ),
    )
    .await;
    assert_eq!(reset.status, StatusCode::OK, "{:?}", reset.body);
    assert_eq!(reset.body["own"], false);
    assert_eq!(
        reset.body["subject"],
        MailKind::Reset.built_in().subject.as_str()
    );
    let sent = server
        .storage
        .mail_templates
        .resolve(&tenant("acme"), MailKind::Reset)
        .await
        .expect("the wording");
    assert_eq!(sent, MailKind::Reset.built_in(), "the default again");
}
