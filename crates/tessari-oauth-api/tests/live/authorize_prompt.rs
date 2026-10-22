//! `max_age`, `prompt=login` and `prompt=none` at the resume step (OpenID Connect Core §3.1.2.1, §3.1.2.6): a sign-in
//! older than the request allows is done again, and a request that asked for no page is answered at its redirect URI
//! with `login_required` or `consent_required` rather than shown one.

use tessari_oauth_core::authentication::Method;
use tessari_oauth_types::{SessionSecret, Timestamp, UserId};

use crate::authorize_resume::{consented, get, resume_path, sent_to, signed_in};
use crate::token_fixture::{NOW, Server, browser, issuer, server, tenant};

/// A session for `user` opened `ago` seconds before now, under the cookie value it answers.
async fn session_from(server: &Server, user: &UserId, ago: u64) -> String {
    let value = format!("a-session-opened-{ago}-seconds-ago");
    server
        .storage
        .sessions
        .create(
            &tenant("acme"),
            &SessionSecret::from_secret(value.clone()),
            user,
            &[Method::Password],
            Timestamp::from_unix_secs(NOW.checked_sub(ago).expect("an instant")),
        )
        .await
        .expect("opened");
    value
}

/// Keep `interaction`'s request again with `change` applied, answering the new id.
async fn kept_with(
    server: &Server,
    interaction: &str,
    change: impl FnOnce(&mut tessari_oauth_core::authorize::AuthorizationRequest),
) -> String {
    let now = Timestamp::from_unix_secs(NOW);
    let mut request = server
        .storage
        .interactions
        .find(&tenant("acme"), interaction, &browser(), now)
        .await
        .expect("the store answers")
        .expect("pending");
    change(&mut request);
    server
        .storage
        .interactions
        .open(&tenant("acme"), &request, &browser(), now)
        .await
        .expect("kept")
}

/// The query pairs of the address `answered` sent the browser to.
fn pairs(answered: &crate::routes::Answer) -> Vec<(String, String)> {
    sent_to(answered).query_pairs().into_owned().collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_sign_in_older_than_max_age_is_done_again_and_a_recent_one_is_answered() {
    let server = server(2).await;
    let (interaction, _, user) = signed_in(&server, "noether@example.com").await;
    consented(&server, &user).await;
    let hour_old = session_from(&server, &user, 3_600).await;
    let strict = kept_with(&server, &interaction, |request| request.max_age = Some(600)).await;
    let answered = get(&server, &resume_path(&strict), Some(&hour_old)).await;
    assert_eq!(
        sent_to(&answered).as_str(),
        format!("{}/login?interaction={strict}", issuer("acme")),
        "an hour-old sign-in under max_age=600 is done again"
    );
    let login = kept_with(&server, &interaction, |request| request.max_age = Some(0)).await;
    let answered = get(&server, &resume_path(&login), Some(&hour_old)).await;
    assert!(
        sent_to(&answered).path().ends_with("/login"),
        "prompt=login"
    );
    let loose = kept_with(&server, &interaction, |request| {
        request.max_age = Some(7_200)
    })
    .await;
    let answered = get(&server, &resume_path(&loose), Some(&hour_old)).await;
    let names: Vec<String> = pairs(&answered).into_iter().map(|(name, _)| name).collect();
    assert_eq!(names, ["code", "iss"], "within max_age a code is answered");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_that_asked_for_no_page_is_answered_at_its_redirect_uri() {
    let server = server(2).await;
    let (interaction, session, user) = signed_in(&server, "germain@example.com").await;
    let silent = |state: &str| {
        let state = state.to_owned();
        move |request: &mut tessari_oauth_core::authorize::AuthorizationRequest| {
            request.silent = true;
            request.state = Some(state);
        }
    };
    let no_session = kept_with(&server, &interaction, silent("s1")).await;
    let answered = get(&server, &resume_path(&no_session), None).await;
    assert_eq!(
        pairs(&answered),
        [
            ("error".to_owned(), "login_required".to_owned()),
            ("state".to_owned(), "s1".to_owned()),
            ("iss".to_owned(), issuer("acme")),
        ]
    );
    let no_consent = kept_with(&server, &interaction, silent("s2")).await;
    let answered = get(&server, &resume_path(&no_consent), Some(&session)).await;
    assert_eq!(pairs(&answered)[0].1, "consent_required");
    consented(&server, &user).await;
    let hour_old = session_from(&server, &user, 3_600).await;
    let too_old = kept_with(&server, &interaction, |request| {
        request.silent = true;
        request.max_age = Some(600);
    })
    .await;
    let answered = get(&server, &resume_path(&too_old), Some(&hour_old)).await;
    assert_eq!(pairs(&answered)[0].1, "login_required");
}
