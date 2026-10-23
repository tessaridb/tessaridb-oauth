//! Self-registration over a live store: closed by default and then not there at all; open, every address answers
//! alike while its mailbox learns the rest: a new account gets an enrolment link, an account with no password a new
//! one, an account that signs in a notice, a disabled account nothing. Domains, budgets and the relay refuse alike.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_core::registration::RegistrationPolicy;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::outbox::QueuedMail;
use tessari_oauth_storage::users::UserStatus;
use tessari_oauth_types::{EmailAddress, EnrolmentCode};
use tower::ServiceExt as _;

use crate::login::{post, post_from, register};
use crate::login_password::with_password;
use crate::routes::{Answer, answer};
use crate::token_fixture::{Server, plenty, server, state, tenant};

const LINK: &str = "https://id.example.com/acme/login/enrol#code=";
const PEER: [u8; 4] = [192, 0, 2, 7];

/// Open `acme` to registration from addresses at `domains`, or at any address when there are none.
async fn open(server: &Server, domains: &[&str]) {
    let names = domains.iter().map(|name| (*name).to_owned()).collect();
    let policy = RegistrationPolicy::new(true, names).expect("a valid policy");
    let made = server
        .storage
        .policies
        .set_registration(&tenant("acme"), 0, &policy)
        .await
        .expect("kept");
    assert_eq!(made, Some(1));
}

/// Every mail queued in `acme`, opened.
async fn queued(server: &Server) -> Vec<QueuedMail> {
    server
        .storage
        .outbox
        .claim(&tenant("acme"), &server.kek, 50)
        .await
        .expect("claimed")
}

/// The one mail `mails` holds for `address`.
fn mail_to<'a>(mails: &'a [QueuedMail], address: &str) -> &'a QueuedMail {
    let to: Vec<&QueuedMail> = mails
        .iter()
        .filter(|mail| mail.to.as_ref().map(EmailAddress::as_str) == Some(address))
        .collect();
    assert_eq!(to.len(), 1, "{mails:?}");
    to[0]
}

/// The enrolment code the link in `mail` carries.
fn code_in(mail: &QueuedMail) -> EnrolmentCode {
    let (_, after) = mail.text.split_once(LINK).expect("an enrolment link");
    EnrolmentCode::from_secret(after.split_whitespace().next().expect("a code").to_owned())
}

/// `POST .../register` for `email` from `peer`.
async fn register_from(server: &Server, peer: [u8; 4], email: &str) -> Answer {
    let body = json!({ "email": email }).to_string();
    post_from(
        server,
        plenty(),
        SocketAddr::from((peer, 443)),
        "register",
        None,
        body,
    )
    .await
}

/// `GET .../registration`.
async fn read_policy(server: &Server) -> Answer {
    let request = Request::get("/acme/login/api/registration")
        .extension(ConnectInfo(SocketAddr::from((PEER, 443))))
        .body(Body::empty())
        .expect("a request");
    answer(
        public_router(state(server, plenty()))
            .oneshot(request)
            .await
            .expect("the router answers"),
    )
    .await
}

/// The reasons of every `account_registered` record, oldest first.
async fn registrations(server: &Server) -> Vec<Option<String>> {
    server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .map(|record| record.event)
        .filter(|event| event.kind == AuditKind::AccountRegistered)
        .map(|event| event.reason)
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_closed_company_has_no_registration_and_says_only_that_it_is_closed() {
    let server = server(2).await;
    let read = read_policy(&server).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body, json!({ "open": false }));

    let asked = register_from(&server, PEER, "new@example.com").await;
    assert_eq!(asked.status, StatusCode::NOT_FOUND);
    assert!(queued(&server).await.is_empty());
    assert!(registrations(&server).await.is_empty());

    open(&server, &["example.com"]).await;
    assert_eq!(
        read_policy(&server).await.body,
        json!({ "open": true }),
        "the domains are not read out"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_address_answers_alike_and_only_its_mailbox_learns_which_it_was() {
    let server = server(2).await;
    open(&server, &[]).await;
    let waiting = register(&server, "waiting@example.com").await;
    with_password(&server, "owner@example.com").await;
    let gone = register(&server, "gone@example.com").await;
    let disabled = server
        .storage
        .users
        .set_status(
            &tenant("acme"),
            &gone,
            UserStatus::Active,
            UserStatus::Disabled,
        )
        .await
        .expect("disabled");
    assert!(disabled);

    let addresses = [
        "new@example.com",
        "waiting@example.com",
        "owner@example.com",
        "gone@example.com",
    ];
    let mut answers = Vec::new();
    for address in addresses {
        answers.push(register_from(&server, PEER, address).await);
    }
    for answered in &answers {
        assert_eq!(answered.status, StatusCode::ACCEPTED, "{}", answered.body);
        assert_eq!(answered.body, answers[0].body);
    }

    let mails = queued(&server).await;
    assert_eq!(
        mails.len(),
        4,
        "one mail each, the disabled account's to nobody: {mails:?}"
    );
    assert_eq!(
        mails.iter().filter(|mail| mail.to.is_none()).count(),
        1,
        "{mails:?}"
    );
    let created = server
        .storage
        .users
        .find_by_email(
            &tenant("acme"),
            &EmailAddress::parse("new@example.com").expect("an address"),
        )
        .await
        .expect("an answer")
        .expect("the account was opened");
    assert!(
        !created.email_verified,
        "the address is verified only by its own link"
    );
    assert_eq!(created.status, UserStatus::Active);
    for (address, user) in [
        ("new@example.com", &created.user),
        ("waiting@example.com", &waiting),
    ] {
        let code = code_in(mail_to(&mails, address));
        let holder = server
            .storage
            .enrolments
            .find(&tenant("acme"), &code)
            .await
            .expect("an answer");
        assert_eq!(
            holder.as_ref(),
            Some(user),
            "{address}'s link enrols that account"
        );
    }
    let notice = mail_to(&mails, "owner@example.com");
    assert!(
        !notice.text.contains(LINK),
        "an owner's notice carries no enrolment link"
    );
    assert!(notice.text.contains("already signs in"), "{}", notice.text);
    assert!(
        server
            .storage
            .users
            .password(&tenant("acme"), &created.user)
            .await
            .expect("an answer")
            .is_none(),
        "registration sets no password"
    );
    assert_eq!(
        registrations(&server).await,
        ["created", "code_renewed", "existing_notified", "disabled"]
            .map(|reason| Some(reason.to_owned())),
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn asking_again_replaces_the_link_so_only_the_newest_enrols() {
    let server = server(2).await;
    open(&server, &[]).await;
    register_from(&server, PEER, "new@example.com").await;
    let first = code_in(mail_to(&queued(&server).await, "new@example.com"));
    register_from(&server, PEER, "new@example.com").await;
    let second = code_in(mail_to(&queued(&server).await, "new@example.com"));

    let enrolments = &server.storage.enrolments;
    assert_eq!(
        enrolments
            .find(&tenant("acme"), &first)
            .await
            .expect("an answer"),
        None
    );
    assert!(
        enrolments
            .find(&tenant("acme"), &second)
            .await
            .expect("an answer")
            .is_some()
    );
    assert_eq!(
        registrations(&server).await,
        [Some("created".to_owned()), Some("code_renewed".to_owned())],
        "one account, opened once"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_domain_list_refuses_every_other_domain_alike_and_a_malformed_address_is_refused() {
    let server = server(2).await;
    open(&server, &["example.com"]).await;
    with_password(&server, "owner@elsewhere.org").await;

    for address in [
        "new@elsewhere.org",
        "owner@elsewhere.org",
        "new@mail.example.com",
    ] {
        let refused = register_from(&server, PEER, address).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{address}");
        assert_eq!(refused.body["code"], "address_not_accepted", "{address}");
    }
    let malformed = register_from(&server, PEER, "not an address").await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert_eq!(malformed.body["code"], "email_rejected");
    assert_eq!(
        register_from(&server, PEER, "new@example.com").await.status,
        StatusCode::ACCEPTED
    );
    let mails = queued(&server).await;
    assert_eq!(mails.len(), 1, "{mails:?}");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_address_and_a_source_each_have_a_budget_and_past_it_the_answer_is_the_same_wait() {
    let server = server(2).await;
    open(&server, &[]).await;
    for _ in 0..3 {
        let asked = register_from(&server, PEER, "new@example.com").await;
        assert_eq!(asked.status, StatusCode::ACCEPTED);
    }
    let fourth = register_from(&server, [192, 0, 2, 8], "new@example.com").await;
    assert_eq!(
        fourth.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the address's budget holds from any source"
    );

    let busy = [198, 51, 100, 9];
    for at in 0..10 {
        let asked = register_from(&server, busy, &format!("person{at}@example.com")).await;
        assert_eq!(asked.status, StatusCode::ACCEPTED, "{at}");
    }
    let past = register_from(&server, busy, "person99@example.com").await;
    assert_eq!(
        past.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the source's budget holds for any address"
    );
    assert_eq!(
        queued(&server).await.len(),
        13,
        "nothing past a budget is sent"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_a_relay_an_open_company_refuses_every_address_alike() {
    let server = server(2).await;
    open(&server, &[]).await;
    with_password(&server, "owner@example.com").await;
    let mut public = state(&server, plenty());
    public.mail = false;
    for email in ["owner@example.com", "new@example.com"] {
        let request = Request::post("/acme/login/api/register")
            .header("content-type", "application/json")
            .extension(ConnectInfo(SocketAddr::from((PEER, 443))))
            .body(Body::from(json!({ "email": email }).to_string()))
            .expect("a request");
        let answered = answer(
            public_router(public.clone())
                .oneshot(request)
                .await
                .expect("answered"),
        )
        .await;
        assert_eq!(answered.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answered.body["code"], "mail_unavailable");
    }
    assert!(queued(&server).await.is_empty());
    let unused = post(&server, "register", None, json!({})).await;
    assert_eq!(
        unused.status,
        StatusCode::BAD_REQUEST,
        "a body with no address is unreadable"
    );
}
