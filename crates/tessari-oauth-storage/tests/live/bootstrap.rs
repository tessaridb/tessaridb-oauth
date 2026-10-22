//! The emergency path: it makes the `system` company and an operator in it who holds `companies` and `users`, or the
//! first operator of a company that already exists and is served, who holds that company's four console roles; it
//! hands the operator a code to set a first password and leaves its use on that company's audit trail every time.

use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::companies::CompanyStatus;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::StoredPassword;
use tessari_oauth_storage::{Bootstrapped, Error, Storage};
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

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

/// The company `id`, made and served, then moved to `status` when that is not `Active`.
async fn company(storage: &Storage, id: &TenantId, status: CompanyStatus) {
    storage.companies.prepare().await.expect("the directory");
    storage
        .companies
        .create(id, "Acme", "test", NOW)
        .await
        .expect("created");
    storage
        .provision_company(id, PUBLIC, CONSOLE, NOW)
        .await
        .expect("provisioned");
    storage
        .companies
        .transition(id, CompanyStatus::Provisioning, CompanyStatus::Active)
        .await
        .expect("activated");
    if status != CompanyStatus::Active {
        storage
            .companies
            .transition(id, CompanyStatus::Active, status)
            .await
            .expect("moved");
    }
}

async fn roles(storage: &Storage, done: &Bootstrapped) -> Vec<OperatorRole> {
    roles_in(storage, &system(), done).await
}

async fn roles_in(storage: &Storage, company: &TenantId, done: &Bootstrapped) -> Vec<OperatorRole> {
    let mut roles: Vec<OperatorRole> = storage
        .operators
        .grants(company, &done.user, NOW)
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
        .bootstrap_operator(&system(), &email(), &code, PUBLIC, CONSOLE, NOW)
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
        .bootstrap_operator(&system(), &email(), &first, PUBLIC, CONSOLE, NOW)
        .await
        .expect("bootstrapped");
    let twice = storage
        .bootstrap_operator(&system(), &email(), &second, PUBLIC, CONSOLE, NOW)
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
            &system(),
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
        .bootstrap_operator(&system(), &email(), &code, PUBLIC, CONSOLE, NOW)
        .await
        .expect("bootstrapped again");
    assert!(!again.code_issued);
    assert_eq!(storage.enrolments.find(&system(), &code).await, Ok(None));
    assert_eq!(
        roles(&storage, &again).await,
        [OperatorRole::Companies, OperatorRole::Users]
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_served_company_gets_its_first_operator_with_its_four_roles() {
    let storage = storage();
    company(&storage, &acme(), CompanyStatus::Active).await;
    let code = EnrolmentCode::from_secret("code-acme");
    let done = storage
        .bootstrap_operator(&acme(), &email(), &code, PUBLIC, CONSOLE, NOW)
        .await
        .expect("bootstrapped");
    assert!(done.code_issued);
    assert_eq!(
        roles_in(&storage, &acme(), &done).await,
        [
            OperatorRole::Audit,
            OperatorRole::Clients,
            OperatorRole::Policy,
            OperatorRole::Users
        ],
        "every console role but companies, which only system users hold"
    );
    assert_eq!(
        storage.enrolments.find(&acme(), &code).await,
        Ok(Some(done.user.clone()))
    );
    let trail = storage
        .audit
        .read_after(&acme(), 0, 100)
        .await
        .expect("the trail");
    assert_eq!(
        &trail.last().expect("a message").event,
        &AuditEvent {
            user: Some(done.user.clone()),
            actor: Some("break-glass".to_owned()),
            reason: Some("bootstrap-operator".to_owned()),
            ..AuditEvent::of(AuditKind::BreakGlass)
        }
    );
    assert_eq!(
        storage.companies.find(&system()).await,
        Ok(None),
        "the system company is not made for another company's operator"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_suspended_or_unknown_company_is_refused_and_nothing_is_written() {
    let storage = storage();
    company(&storage, &acme(), CompanyStatus::Suspended).await;
    let unknown = TenantId::parse("globex").expect("a tenant id");
    for target in [acme(), unknown.clone()] {
        let refused = storage
            .bootstrap_operator(
                &target,
                &email(),
                &EnrolmentCode::from_secret("c"),
                PUBLIC,
                CONSOLE,
                NOW,
            )
            .await;
        assert!(
            matches!(
                refused,
                Err(Error::Invalid {
                    record: "company",
                    ..
                })
            ),
            "{target:?}: {refused:?}"
        );
    }
    assert_eq!(
        storage.users.find_by_email(&acme(), &email()).await,
        Ok(None)
    );
    assert_eq!(storage.companies.find(&unknown).await, Ok(None));
}
