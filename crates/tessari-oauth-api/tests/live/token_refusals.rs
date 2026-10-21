//! What the token endpoint refuses: each broken binding of a code, and each request whose client or shape is wrong —
//! every refusal with the specification's `error` code and nothing the request supplied, never stored by a cache.

use axum::http::StatusCode;

use crate::routes::{Answer, header};
use crate::token_fixture::{NOW, Server, issue, post, post_raw, redemption, server, uncached};

/// A verifier of the right shape that is not the one the codes were issued for.
const WRONG_VERIFIER: &str = "another-verifier-0123456789-0123456789-0123456789";

/// `answer` is a refusal with `status` and `error`, and says nothing else.
fn refused(answer: &Answer, status: StatusCode, error: &str, case: &str) {
    assert_eq!(answer.status, status, "{case}: {}", answer.body);
    assert_eq!(answer.body["error"], error, "{case}");
    assert_eq!(
        answer.body.as_object().map(serde_json::Map::len),
        Some(1),
        "{case}: {}",
        answer.body
    );
    uncached(answer);
}

/// Redeem the code `secret` with `pairs` replacing or adding to a correct redemption, minus the names in `drop`.
async fn redeem_changed(
    server: &Server,
    tenant: &str,
    secret: &str,
    changed: &[(&str, &str)],
    drop: &[&str],
) -> Answer {
    let mut pairs: Vec<(&str, &str)> = redemption("portal", secret)
        .into_iter()
        .filter(|(name, _)| !drop.contains(name) && !changed.iter().any(|(other, _)| other == name))
        .collect();
    pairs.extend_from_slice(changed);
    post(server, tenant, &pairs).await
}

/// A redemption with one binding broken: the code as issued (to `portal`, unless named; `None` for a code never
/// issued), the parameters changed or dropped, and the `error` expected.
struct Broken<'a> {
    case: &'a str,
    issued_to: Option<&'a str>,
    expires_at: u64,
    changed: &'a [(&'a str, &'a str)],
    dropped: &'a [&'a str],
    error: &'a str,
}

impl<'a> Broken<'a> {
    const fn new(case: &'a str, error: &'a str) -> Self {
        Self {
            case,
            issued_to: Some("portal"),
            expires_at: NOW + 60,
            changed: &[],
            dropped: &[],
            error,
        }
    }

    const fn changing(self, changed: &'a [(&'a str, &'a str)]) -> Self {
        Self { changed, ..self }
    }

    const fn dropping(self, dropped: &'a [&'a str]) -> Self {
        Self { dropped, ..self }
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_broken_binding_of_a_code_is_refused() {
    let server = server(2).await;
    let cases = [
        Broken::new("wrong verifier", "invalid_grant")
            .changing(&[("code_verifier", WRONG_VERIFIER)]),
        Broken::new("absent verifier", "invalid_grant").dropping(&["code_verifier"]),
        Broken::new("other redirect URI", "invalid_grant")
            .changing(&[("redirect_uri", "https://app.example.com/callback/")]),
        Broken {
            expires_at: NOW,
            ..Broken::new("expired code", "invalid_grant")
        },
        Broken {
            issued_to: Some("kiosk"),
            ..Broken::new("another client's code", "invalid_grant")
        },
        Broken::new("resource not granted", "invalid_target")
            .changing(&[("resource", "https://other.example.com/")]),
        Broken {
            issued_to: None,
            ..Broken::new("unknown code", "invalid_grant")
        },
    ];
    for (index, broken) in cases.into_iter().enumerate() {
        let secret = format!("code-{index}");
        if let Some(client) = broken.issued_to {
            issue(&server, "acme", client, &secret, broken.expires_at).await;
        }
        let answer = redeem_changed(&server, "acme", &secret, broken.changed, broken.dropped).await;
        refused(&answer, StatusCode::BAD_REQUEST, broken.error, broken.case);
    }
    // A code issued in one tenant does not redeem at another, even for a client of the same name.
    issue(&server, "acme", "portal", "code-acme", NOW + 60).await;
    let crossed = redeem_changed(&server, "initech", "code-acme", &[], &[]).await;
    refused(
        &crossed,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "cross-tenant code",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_with_the_wrong_client_or_shape_is_refused() {
    let server = server(2).await;
    issue(&server, "acme", "portal", "code-shape", NOW + 60).await;

    let unknown = post(&server, "acme", &redemption("ghost", "code-shape")).await;
    refused(
        &unknown,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "unknown client",
    );

    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(redemption("portal", "code-shape"))
        .finish();
    let content = "application/x-www-form-urlencoded";
    let basic = post_raw(
        &server,
        "acme",
        content,
        form.clone(),
        Some("Basic cG9ydGFsOnNlY3JldA=="),
    )
    .await;
    refused(
        &basic,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "HTTP Basic, not the pinned method",
    );
    assert!(header(&basic, "www-authenticate").starts_with("Basic"));

    let json = post_raw(
        &server,
        "acme",
        "application/json",
        r#"{"grant_type":"authorization_code"}"#.to_owned(),
        None,
    )
    .await;
    refused(
        &json,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "JSON body",
    );

    let oversize = format!("{form}&padding={}", "x".repeat(16 * 1024));
    let large = post_raw(&server, "acme", content, oversize, None).await;
    refused(
        &large,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "body over the cap",
    );

    let mut repeated = redemption("portal", "code-shape");
    repeated.push(("code", "code-other"));
    refused(
        &post(&server, "acme", &repeated).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "repeated parameter",
    );

    let mut two_methods = redemption("portal", "code-shape");
    two_methods.extend([("client_secret", "secret"), ("client_assertion", "a.b.c")]);
    refused(
        &post(&server, "acme", &two_methods).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "two methods",
    );

    let refresh = [
        ("grant_type", "refresh_token"),
        ("client_id", "portal"),
        ("refresh_token", "r"),
    ];
    refused(
        &post(&server, "acme", &refresh).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "refresh token nobody issued",
    );

    let unregistered = [
        ("grant_type", "refresh_token"),
        ("client_id", "kiosk"),
        ("refresh_token", "r"),
    ];
    refused(
        &post(&server, "acme", &unregistered).await,
        StatusCode::BAD_REQUEST,
        "unauthorized_client",
        "grant not registered",
    );

    // None of the refusals above spent the code: a correct redemption still succeeds.
    let after = post(&server, "acme", &redemption("portal", "code-shape")).await;
    assert_eq!(after.status, StatusCode::OK, "{}", after.body);
}
