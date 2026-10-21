//! The revocation endpoint (RFC 7009): a client revokes its refresh token, whose whole family then stops working;
//! an unknown token answers the same; another client's token is refused and left usable; an access token, which is
//! never recalled, is refused as a type the server does not revoke; and the client authenticates as at `/token`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tessari_oauth_api::public_router;
use tower::ServiceExt;

use crate::routes::{Answer, answer};
use crate::token_auth::{ASSERTION_TYPE, assertion};
use crate::token_client_credentials::machine;
use crate::token_fixture::{NOW, Server, issue, plenty, post, redemption, server, state, uncached};

/// POST `pairs` as a form to `acme`'s revocation endpoint, with `authorization` when given.
async fn revoke(server: &Server, pairs: &[(&str, &str)], authorization: Option<&str>) -> Answer {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut request = Request::post("/acme/oauth2/revoke")
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(credentials) = authorization {
        request = request.header("authorization", credentials);
    }
    let response = public_router(state(server, plenty()))
        .oneshot(request.body(Body::from(body)).expect("a request"))
        .await
        .expect("the router answers");
    answer(response).await
}

/// A refresh token `portal` holds, from the code `secret`.
async fn held(server: &Server, secret: &str) -> String {
    issue(server, "acme", "portal", secret, NOW + 60).await;
    let issued = post(server, "acme", &redemption("portal", secret)).await;
    assert_eq!(issued.status, StatusCode::OK, "{}", issued.body);
    issued.body["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned()
}

fn refresh(token: &str) -> Vec<(&str, &str)> {
    vec![
        ("grant_type", "refresh_token"),
        ("client_id", "portal"),
        ("refresh_token", token),
    ]
}

fn revoked(answer: &Answer, case: &str) {
    assert_eq!(answer.status, StatusCode::OK, "{case}: {}", answer.body);
    assert!(
        answer.body.is_null(),
        "{case}: an empty body, got {}",
        answer.body
    );
    uncached(answer);
}

fn refused(answer: &Answer, status: StatusCode, error: &str, case: &str) {
    assert_eq!(answer.status, status, "{case}: {}", answer.body);
    assert_eq!(answer.body["error"], error, "{case}");
    uncached(answer);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_revoked_refresh_token_and_its_family_stop_working() {
    let server = server(2).await;
    let token = held(&server, "code-v1").await;
    let rotated = post(&server, "acme", &refresh(&token)).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let successor = rotated.body["refresh_token"]
        .as_str()
        .expect("a successor")
        .to_owned();

    revoked(
        &revoke(
            &server,
            &[
                ("client_id", "portal"),
                ("token", &successor),
                ("token_type_hint", "refresh_token"),
            ],
            None,
        )
        .await,
        "the live token",
    );
    refused(
        &post(&server, "acme", &refresh(&successor)).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "refreshing after the revocation",
    );
    revoked(
        &revoke(
            &server,
            &[("client_id", "portal"), ("token", &successor)],
            None,
        )
        .await,
        "revoking again",
    );
    revoked(
        &revoke(
            &server,
            &[("client_id", "portal"), ("token", "never-issued")],
            None,
        )
        .await,
        "an unknown token",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn only_its_own_refresh_token_is_revoked_and_never_an_access_token() {
    let server = server(2).await;
    let token = held(&server, "code-v2").await;
    refused(
        &revoke(&server, &[("client_id", "kiosk"), ("token", &token)], None).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "another client's token",
    );
    let still = post(&server, "acme", &refresh(&token)).await;
    assert_eq!(still.status, StatusCode::OK, "left usable: {}", still.body);
    let access = still.body["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned();

    refused(
        &revoke(
            &server,
            &[("client_id", "portal"), ("token", &access)],
            None,
        )
        .await,
        StatusCode::BAD_REQUEST,
        "unsupported_token_type",
        "an access token",
    );
    // A hint is only a hint (RFC 7009 §2.1): a refresh token hinted as an access token is still found and revoked.
    let hinted = still.body["refresh_token"]
        .as_str()
        .expect("a successor")
        .to_owned();
    revoked(
        &revoke(
            &server,
            &[
                ("client_id", "portal"),
                ("token", &hinted),
                ("token_type_hint", "access_token"),
            ],
            None,
        )
        .await,
        "a refresh token hinted as an access token",
    );
    refused(
        &post(&server, "acme", &refresh(&hinted)).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "refreshing the hinted token after its revocation",
    );
    refused(
        &revoke(&server, &[("client_id", "portal")], None).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "no token",
    );
    refused(
        &revoke(
            &server,
            &[("token", "x")],
            Some("Basic cG9ydGFsOnNlY3JldA=="),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "a client that does not authenticate as registered",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_confidential_client_revokes_only_once_it_authenticates() {
    let server = server(2).await;
    let key = machine(&server).await;
    refused(
        &revoke(&server, &[("client_id", "machine"), ("token", "x")], None).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "the client named without its assertion",
    );
    let signed = assertion(&key, "machine", "revoke-1");
    revoked(
        &revoke(
            &server,
            &[
                ("client_id", "machine"),
                ("token", "x"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", signed.as_str()),
            ],
            None,
        )
        .await,
        "the client authenticated",
    );
}
