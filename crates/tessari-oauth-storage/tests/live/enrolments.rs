//! Enrolment codes: a code enrols its user once; a second code for the same user replaces the first; a code nobody
//! issued enrols nobody.

use tessari_oauth_types::{EnrolmentCode, TenantId, Timestamp, UserId};

use crate::fresh;

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn user(raw: &str) -> UserId {
    UserId::parse(raw).expect("a user id")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_code_enrols_its_user_once() {
    let storage = fresh(&acme(), 2).await;
    let code = EnrolmentCode::from_secret("code-1");
    storage
        .enrolments
        .issue(
            &acme(),
            &code,
            &user("user-1"),
            "operator-1",
            Timestamp::from_unix_secs(1),
        )
        .await
        .expect("issued");
    let first = storage
        .enrolments
        .redeem(&acme(), &code)
        .await
        .expect("an answer");
    assert_eq!(first, Some(user("user-1")));
    let second = storage
        .enrolments
        .redeem(&acme(), &code)
        .await
        .expect("an answer");
    assert_eq!(second, None, "spent");
    let unknown = storage
        .enrolments
        .redeem(&acme(), &EnrolmentCode::from_secret("never-issued"))
        .await
        .expect("an answer");
    assert_eq!(unknown, None);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_new_code_replaces_the_users_earlier_one_and_no_other() {
    let storage = fresh(&acme(), 2).await;
    let at = Timestamp::from_unix_secs(1);
    let (old, new, other) = (
        EnrolmentCode::from_secret("code-old"),
        EnrolmentCode::from_secret("code-new"),
        EnrolmentCode::from_secret("code-other"),
    );
    for (code, account) in [(&old, "user-1"), (&other, "user-2"), (&new, "user-1")] {
        storage
            .enrolments
            .issue(&acme(), code, &user(account), "operator-1", at)
            .await
            .expect("issued");
    }
    assert_eq!(
        storage
            .enrolments
            .redeem(&acme(), &old)
            .await
            .expect("an answer"),
        None
    );
    assert_eq!(
        storage
            .enrolments
            .redeem(&acme(), &other)
            .await
            .expect("an answer"),
        Some(user("user-2"))
    );
    assert_eq!(
        storage
            .enrolments
            .redeem(&acme(), &new)
            .await
            .expect("an answer"),
        Some(user("user-1"))
    );
}
