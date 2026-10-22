//! The emergency path: it makes the `system` company and an operator in it who holds `companies` and `users`, hands
//! the operator a code to set a first password, and leaves its use on the audit trail every time it runs.

use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::companies::CompanyStatus;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::StoredPassword;
use tessari_oauth_storage::{Bootstrapped, Storage};
use tessari_oauth_test_support::plain_node;
use tessari_oauth_types::{EmailAddress, EnrolmentCode, TenantId, Timestamp};

use crate::fresh_on;

const PUBLIC: &str = "https://id.example.com";

const CONSOLE: &str = "https://admin.example.com";

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

fn system() -> TenantId {
    TenantId::parse("system").expect("a tenant id")
}

fn email() -> EmailAddress {
    EmailAddress::parse("root@example.com").expect("an address")
}

fn storage() -> Storage {
    fresh_on(plain_node().expect("the plain node is named"), 2)
}

async fn roles(storage: &Storage, done: &Bootstrapped) -> Vec<OperatorRole> {
    let mut roles: Vec<OperatorRole> = storage
        .operators
        .grants(&system(), &done.user, NOW)
        .await
        .expect("an answer")
        .into_iter()
        .map(|grant| grant.role)
        .collect();
    roles.sort_by_key(|role| role.name());
    roles
}

async fn kinds(storage: &Storage) -> Vec<AuditKind> {
    storage
        .audit
        .read_after(&system(), 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .map(|record| record.event.kind)
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_first_operator_is_made_in_an_active_system_company() {
    let storage = storage();
    let code = EnrolmentCode::from_secret("code-1");
    let done = storage
        .bootstrap_operator(&email(), &code, PUBLIC, CONSOLE, NOW)
        .await
        .expect("bootstrapped");
    assert!(done.code_issued);
    let company = storage
        .companies
        .find(&system())
        .await
        .expect("an answer")
        .expect("the system company");
    assert_eq!(company.status, CompanyStatus::Active);
    let account = storage
        .users
        .find_by_email(&system(), &email())
        .await
        .expect("an answer")
        .expect("the operator's account");
    assert_eq!(account.user, done.user);
    assert_eq!(
        roles(&storage, &done).await,
        [OperatorRole::Companies, OperatorRole::Users]
    );
    assert_eq!(
        storage.enrolments.find(&system(), &code).await,
        Ok(Some(done.user.clone()))
    );
    let trail = storage
        .audit
        .read_after(&system(), 0, 100)
        .await
        .expect("the trail");
    let last = &trail.last().expect("a message").event;
    assert_eq!(
        last,
        &AuditEvent {
            user: Some(done.user.clone()),
            actor: Some("break-glass".to_owned()),
            reason: Some("bootstrap-operator".to_owned()),
            ..AuditEvent::of(AuditKind::BreakGlass)
        }
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn running_it_again_reaches_the_same_account_with_a_new_code() {
    let storage = storage();
    let first = EnrolmentCode::from_secret("code-1");
    let second = EnrolmentCode::from_secret("code-2");
    let once = storage
        .bootstrap_operator(&email(), &first, PUBLIC, CONSOLE, NOW)
        .await
        .expect("bootstrapped");
    let twice = storage
        .bootstrap_operator(&email(), &second, PUBLIC, CONSOLE, NOW)
        .await
        .expect("bootstrapped again");
    assert_eq!(once.user, twice.user, "one account");
    assert_eq!(storage.enrolments.find(&system(), &first).await, Ok(None));
    assert_eq!(
        storage.enrolments.find(&system(), &second).await,
        Ok(Some(twice.user.clone()))
    );
    assert_eq!(
        roles(&storage, &twice).await,
        [OperatorRole::Companies, OperatorRole::Users]
    );
    let uses = kinds(&storage)
        .await
        .into_iter()
        .filter(|kind| *kind == AuditKind::BreakGlass)
        .count();
    assert_eq!(uses, 2, "every use is on the trail");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_account_that_has_a_password_is_given_no_code() {
    let storage = storage();
    let done = storage
        .bootstrap_operator(
            &email(),
            &EnrolmentCode::from_secret("code-1"),
            PUBLIC,
            CONSOLE,
            NOW,
        )
        .await
        .expect("bootstrapped");
    let password = StoredPassword {
        hash: "$argon2id$v=19$m=131072,t=3,p=1$c2FsdA$aGFzaA".to_owned(),
        pepper: 1,
    };
    storage
        .users
        .set_password(&system(), &done.user, &password, NOW)
        .await
        .expect("set");
    let code = EnrolmentCode::from_secret("code-2");
    let again = storage
        .bootstrap_operator(&email(), &code, PUBLIC, CONSOLE, NOW)
        .await
        .expect("bootstrapped again");
    assert!(!again.code_issued);
    assert_eq!(storage.enrolments.find(&system(), &code).await, Ok(None));
    assert_eq!(
        roles(&storage, &again).await,
        [OperatorRole::Companies, OperatorRole::Users]
    );
}
