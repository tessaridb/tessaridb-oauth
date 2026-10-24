//! A company's brand in its console, set by an operator holding `policy`: replaced whole and only from the revision
//! the operator read, every value read by the type the server keeps it as, and a logo stored only as the server's own
//! re-encoding of the PNG it was sent. Each change carries its reason and is made once per `Idempotency-Key`.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tessari_oauth_api::admin_router;
use tessari_oauth_core::logo::reencode;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::base64url;
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const BRANDING: &str = "/admin/acme/api/branding";
const LOGO: &str = "/admin/acme/api/branding/logo";
const LOGO_REMOVE: &str = "/admin/acme/api/branding/logo/remove";

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
    Request::get(BRANDING)
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

/// A one-pixel PNG carrying a text chunk, as an upload might.
fn upload() -> Vec<u8> {
    let mut sent = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut sent, 1, 1);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .add_text_chunk("Comment".to_owned(), "<script>x</script>".to_owned())
            .expect("a text chunk");
        let mut writer = encoder.write_header().expect("a header");
        writer
            .write_image_data(&[200, 30, 30, 255])
            .expect("a pixel");
    }
    sent
}

const ACME: &str = concat!(
    r##"{"revision":0,"name":"Acme Bank","accent":"#1f4fd8","##,
    r#""support_url":"https://help.acme.example/","reason":"launch"}"#
);

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_sets_the_brand_once_and_only_from_the_revision_read() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-p",
        &[OperatorRole::Policy],
        "issuer-p",
        "console-p",
    )
    .await;
    let none = send(state.clone(), read()).await;
    assert_eq!(none.status, StatusCode::OK, "{:?}", none.body);
    assert_eq!(none.body["revision"], 0);
    assert!(none.body["name"].is_null() && none.body["logo"].is_null());

    let made = send(
        state.clone(),
        change(Method::PUT, BRANDING, "change-brand-0001", ACME),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    assert_eq!(made.body["revision"], 1);
    assert_eq!(made.body["name"], "Acme Bank");
    assert!(made.body["privacy_url"].is_null());
    let again = send(
        state.clone(),
        change(Method::PUT, BRANDING, "change-brand-0001", ACME),
    )
    .await;
    assert_eq!(again.body, made.body, "answered as the first was");

    let stale = send(
        state.clone(),
        change(Method::PUT, BRANDING, "change-brand-0002", ACME),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["code"], "changed_meanwhile");

    let refusals = [
        (
            r##"{"revision":1,"name":"Acme","accent":"#ffff00","reason":"rebrand"}"##,
            "accent_low_contrast",
        ),
        (
            r#"{"revision":1,"name":"Acme","accent":"blue","reason":"rebrand"}"#,
            "accent_invalid",
        ),
        (
            r##"{"revision":1,"name":"Acme\u202eBank","accent":"#1f4fd8","reason":"rebrand"}"##,
            "brand_name_invalid",
        ),
        (
            r##"{"revision":1,"name":"Acme","accent":"#1f4fd8","support_url":"http://help.acme/","reason":"r"}"##,
            "link_invalid",
        ),
        (
            r##"{"revision":1,"name":"Acme","accent":"#1f4fd8","privacy_url":"javascript:alert(1)","reason":"r"}"##,
            "link_invalid",
        ),
    ];
    for (number, (body, code)) in refusals.into_iter().enumerate() {
        let refused = send(
            state.clone(),
            change(
                Method::PUT,
                BRANDING,
                &format!("change-brand-01{number:02}"),
                body,
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(refused.body["code"], code, "{body}");
    }
    let foreign = send(
        state.clone(),
        change(
            Method::PUT,
            BRANDING,
            "change-brand-0200",
            r##"{"revision":1,"name":"Acme","accent":"#1f4fd8","reason":"x","css":"body{}"}"##,
        ),
    )
    .await;
    assert_eq!(
        foreign.body["code"], "invalid_request",
        "no field outside the brand"
    );

    let replaced = send(
        state.clone(),
        change(
            Method::PUT,
            BRANDING,
            "change-brand-0300",
            r##"{"revision":1,"name":"Acme","accent":"#000000","reason":"rebrand"}"##,
        ),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.body);
    let stored = server
        .storage
        .brands
        .find(&tenant("acme"))
        .await
        .expect("read")
        .expect("a brand");
    assert_eq!(stored.revision, 2);
    assert_eq!(stored.brand.name.as_str(), "Acme");
    assert_eq!(stored.brand.support, None, "replaced whole");

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
                && record.event.action.as_deref() == Some("branding.set")
        })
        .collect();
    assert!(!sets.is_empty(), "the change is recorded");
    assert_eq!(sets[0].event.reason.as_deref(), Some("launch"));
    assert_eq!(sets[0].event.actor.as_deref(), Some("operator-p"));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_logo_is_kept_only_as_the_servers_own_png_and_removed_once() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-p",
        &[OperatorRole::Policy],
        "issuer-p",
        "console-p",
    )
    .await;
    let sent = upload();
    let body = format!(
        r#"{{"png":"{}","reason":"new logo"}}"#,
        base64url::encode(&sent)
    );
    let made = send(
        state.clone(),
        change(Method::PUT, LOGO, "change-logo-0001", &body),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    assert_eq!(made.body["logo"], NOW);
    let kept = server
        .storage
        .brands
        .logo(&tenant("acme"))
        .await
        .expect("read")
        .expect("a logo");
    assert_eq!(kept, reencode(&sent).expect("a png").as_bytes());
    assert!(
        !kept.windows(4).any(|chunk| chunk == b"tEXt"),
        "nothing but pixels survives"
    );
    let read = send(state.clone(), read()).await;
    assert_eq!(read.body["logo"], NOW);

    let refusals = [
        (
            base64url::encode(b"<svg xmlns='http://www.w3.org/2000/svg'/>"),
            "logo_not_png",
        ),
        (
            base64url::encode(&sent[..sent.len() / 2]),
            "logo_unreadable",
        ),
        (base64url::encode(&vec![0; 300 * 1024]), "logo_too_large"),
    ];
    for (number, (png, code)) in refusals.into_iter().enumerate() {
        let refused = send(
            state.clone(),
            change(
                Method::PUT,
                LOGO,
                &format!("change-logo-01{number:02}"),
                &format!(r#"{{"png":"{png}","reason":"try"}}"#),
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{code}");
        assert_eq!(refused.body["code"], code);
    }
    let unreadable = send(
        state.clone(),
        change(
            Method::PUT,
            LOGO,
            "change-logo-0200",
            r#"{"png":"not base64!","reason":"try"}"#,
        ),
    )
    .await;
    assert_eq!(unreadable.body["code"], "invalid_request");
    assert_eq!(
        server
            .storage
            .brands
            .logo(&tenant("acme"))
            .await
            .expect("read"),
        Some(kept),
        "a refused logo leaves the one there"
    );

    let removed = send(
        state.clone(),
        change(
            Method::POST,
            LOGO_REMOVE,
            "change-logo-0300",
            r#"{"reason":"retired"}"#,
        ),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);
    let again = send(
        state.clone(),
        change(
            Method::POST,
            LOGO_REMOVE,
            "change-logo-0301",
            r#"{"reason":"retired"}"#,
        ),
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(again.body["code"], "no_logo");
    assert_eq!(server.storage.brands.logo(&tenant("acme")).await, Ok(None));
}
