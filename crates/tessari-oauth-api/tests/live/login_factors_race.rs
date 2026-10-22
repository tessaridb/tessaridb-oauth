//! A one-time code and a recovery code each presented at once by many sign-ins of one account over a live store:
//! exactly one is accepted, and the others are refused or, once their failures add up, held.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;

use crate::login::post_from;
use crate::login_factors::{ADA, RECOVERY, at_second_factor, current_code, enrolled};
use crate::login_password::account;
use crate::token_fixture::{plenty, server};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn one_code_presented_at_once_by_many_sign_ins_is_accepted_once() {
    let server = Arc::new(server(16).await);
    enrolled(&server).await;
    for (step, code) in [("totp", current_code()), ("recovery", RECOVERY.to_owned())] {
        // The losers of the round before held the address; a new round starts from none.
        server
            .storage
            .throttle
            .signin_succeeded(&account(ADA))
            .await
            .expect("forgotten");
        let mut cookies = Vec::new();
        for _ in 0..16 {
            cookies.push(at_second_factor(&server).await);
        }
        let mut racers = tokio::task::JoinSet::new();
        for (turn, cookie) in cookies.into_iter().enumerate() {
            let (server, code) = (Arc::clone(&server), code.clone());
            let peer =
                SocketAddr::from(([198, 51, 100, u8::try_from(turn).expect("small")], 50_000));
            racers.spawn(async move {
                let body = json!({ "code": code }).to_string();
                post_from(&server, plenty(), peer, step, Some(&cookie), body).await
            });
        }
        let statuses: Vec<StatusCode> = racers
            .join_all()
            .await
            .iter()
            .map(|answered| answered.status)
            .collect();
        let accepted = statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count();
        assert_eq!(accepted, 1, "{step}: {statuses:?}");
        // The others are refused, and once their failures add up, held.
        assert!(
            statuses.iter().all(|status| [
                StatusCode::OK,
                StatusCode::UNAUTHORIZED,
                StatusCode::TOO_MANY_REQUESTS
            ]
            .contains(status)),
            "{step}: {statuses:?}"
        );
    }
}
