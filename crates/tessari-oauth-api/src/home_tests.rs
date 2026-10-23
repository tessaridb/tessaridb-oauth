use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::LOCATION;
use axum::http::{Method, Request, StatusCode};
use axum::routing::get;
use tessari_oauth_storage::companies::{Elsewhere, Served};
use tessari_oauth_types::TenantId;
use tower::ServiceExt;

use super::{Homes, send_home};

const US: &str = "https://us.id.example.com";

fn company(id: &str) -> TenantId {
    TenantId::parse(id).expect("a company id")
}

/// A router answering `/{tenant}/oauth2/token` with 200 whatever the tenant and anything else with 404, behind the
/// layer, on a node serving `acme` while the `us` region serves `beta` and names `acme` too.
fn router() -> Router {
    let served = Arc::new(Served::new("https://eu.id.example.com"));
    served.replace([company("acme")]);
    let elsewhere = Arc::new(Elsewhere::new());
    // A peer naming `acme` too (a company moving between regions) does not take it from this node.
    elsewhere.replace([
        (company("beta"), Arc::from(US)),
        (company("acme"), Arc::from(US)),
    ]);
    Router::new()
        .route(
            "/{tenant}/oauth2/token",
            get(|| async { "served" }).post(|| async { "served" }),
        )
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(axum::middleware::from_fn_with_state(
            Homes { served, elsewhere },
            send_home,
        ))
}

async fn answer(method: Method, uri: &str) -> (StatusCode, Option<String>) {
    let response = router()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from("grant_type=authorization_code"))
                .expect("a request"),
        )
        .await
        .expect("an answer");
    let location = response
        .headers()
        .get(LOCATION)
        .map(|value| value.to_str().expect("text").to_owned());
    (response.status(), location)
}

#[tokio::test]
async fn a_company_another_region_serves_is_sent_there_with_its_path_and_query() {
    assert_eq!(
        answer(
            Method::GET,
            "/beta/.well-known/openid-configuration?x=1&y=%2F"
        )
        .await,
        (
            StatusCode::TEMPORARY_REDIRECT,
            Some(format!(
                "{US}/beta/.well-known/openid-configuration?x=1&y=%2F"
            ))
        )
    );
    assert_eq!(
        answer(Method::GET, "/beta/oauth2/token").await,
        (
            StatusCode::TEMPORARY_REDIRECT,
            Some(format!("{US}/beta/oauth2/token"))
        )
    );
}

#[tokio::test]
async fn a_post_is_sent_with_307_so_its_method_and_body_are_kept() {
    let (status, location) = answer(Method::POST, "/beta/oauth2/token").await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        location.as_deref(),
        Some("https://us.id.example.com/beta/oauth2/token")
    );
}

#[tokio::test]
async fn a_company_served_here_is_answered_here() {
    assert_eq!(
        answer(Method::POST, "/acme/oauth2/token").await,
        (StatusCode::OK, None)
    );
}

#[tokio::test]
async fn a_company_nobody_serves_is_not_found() {
    assert_eq!(
        answer(Method::GET, "/gamma/oauth2/userinfo").await,
        (StatusCode::NOT_FOUND, None)
    );
    assert_eq!(
        answer(Method::GET, "/Not%20an%20id/x").await,
        (StatusCode::NOT_FOUND, None)
    );
    assert_eq!(
        answer(Method::GET, "/").await,
        (StatusCode::NOT_FOUND, None)
    );
}
