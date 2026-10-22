//! Users: an address belongs to one account in its tenant, found by the address whatever its case; a second
//! registration of it — even eight at once — writes nothing; a password credential is replaced whole and read back.

use tessari_oauth_storage::users::{Registered, StoredPassword, UserAccount, UserStatus};
use tessari_oauth_types::{EmailAddress, ErrorCategory, TenantId, Timestamp, UserId};

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn email(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).expect("an address")
}

fn created(registered: Registered) -> UserId {
    match registered {
        Registered::Created(user) => user,
        Registered::AddressTaken => panic!("the address was free"),
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_account_is_found_by_its_address_in_its_own_tenant_only() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    let user = created(
        storage
            .users
            .register(&tenant("acme"), &email("Alice@Example.com"), NOW)
            .await
            .expect("registered"),
    );
    assert_eq!(
        storage
            .users
            .find_by_email(&tenant("acme"), &email("alice@EXAMPLE.com"))
            .await,
        Ok(Some(UserAccount {
            user: user.clone(),
            email: email("alice@example.com"),
            email_verified: false,
            status: UserStatus::Active,
        }))
    );
    assert_eq!(
        storage
            .users
            .find_by_email(&tenant("globex"), &email("alice@example.com"))
            .await,
        Ok(None),
        "another tenant"
    );
    assert_eq!(
        storage
            .users
            .find_by_email(&tenant("acme"), &email("bob@example.com"))
            .await,
        Ok(None),
        "another address"
    );
    let other = created(
        storage
            .users
            .register(&tenant("globex"), &email("alice@example.com"), NOW)
            .await
            .expect("registered"),
    );
    assert_ne!(
        other, user,
        "the same address in another tenant is another account"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_address_belongs_to_one_account_even_when_eight_register_it_at_once() {
    let storage = fresh(&tenant("acme"), 8).await;
    let first = created(
        storage
            .users
            .register(&tenant("acme"), &email("carol@example.com"), NOW)
            .await
            .expect("registered"),
    );
    assert_eq!(
        storage
            .users
            .register(&tenant("acme"), &email("CAROL@example.com"), NOW)
            .await,
        Ok(Registered::AddressTaken)
    );
    let racers = (0..8).map(|_| {
        let storage = storage.clone();
        tokio::spawn(async move {
            storage
                .users
                .register(&tenant("acme"), &email("dave@example.com"), NOW)
                .await
        })
    });
    let mut winners = Vec::new();
    let mut taken = 0_u32;
    for racer in racers {
        match racer.await.expect("the task finished") {
            Ok(Registered::Created(user)) => winners.push(user),
            Ok(Registered::AddressTaken) => taken = taken.saturating_add(1),
            Err(failure) => assert_eq!(
                failure.category(),
                ErrorCategory::Conflict,
                "only contention may refuse: {failure}"
            ),
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "exactly one account; {taken} saw the address taken"
    );
    let found = storage
        .users
        .find_by_email(&tenant("acme"), &email("dave@example.com"))
        .await
        .expect("read")
        .expect("an account");
    assert_eq!(Some(&found.user), winners.first());
    let carol = storage
        .users
        .find_by_email(&tenant("acme"), &email("carol@example.com"))
        .await
        .expect("read")
        .expect("an account");
    assert_eq!(
        carol.user, first,
        "the taken address still names the first account"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_password_credential_is_replaced_whole_and_kept_to_its_account() {
    let storage = fresh(&tenant("acme"), 2).await;
    let user = created(
        storage
            .users
            .register(&tenant("acme"), &email("erin@example.com"), NOW)
            .await
            .expect("registered"),
    );
    assert_eq!(
        storage.users.password(&tenant("acme"), &user).await,
        Ok(None)
    );
    let first = StoredPassword {
        hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA".to_owned(),
        pepper: 1,
    };
    storage
        .users
        .set_password(&tenant("acme"), &user, &first, NOW)
        .await
        .expect("set");
    assert_eq!(
        storage.users.password(&tenant("acme"), &user).await,
        Ok(Some(first))
    );
    let second = StoredPassword {
        hash: "$argon2id$v=19$m=131072,t=3,p=1$c2FsdDI$aGFzaDI".to_owned(),
        pepper: 2,
    };
    storage
        .users
        .set_password(&tenant("acme"), &user, &second, NOW)
        .await
        .expect("set");
    assert_eq!(
        storage.users.password(&tenant("acme"), &user).await,
        Ok(Some(second.clone()))
    );
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    assert_eq!(
        storage.users.password(&tenant("globex"), &user).await,
        Ok(None),
        "another tenant"
    );
    let stranger = UserId::parse("no-such-account").expect("an id");
    assert!(
        matches!(
            storage
                .users
                .set_password(&tenant("acme"), &stranger, &second, NOW)
                .await,
            Err(tessari_oauth_storage::Error::Invalid {
                record: "credential",
                ..
            })
        ),
        "no credential without an account"
    );
    assert_eq!(
        storage.users.password(&tenant("acme"), &stranger).await,
        Ok(None)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn accounts_are_listed_page_by_page_in_id_order_with_their_addresses() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let mut registered = Vec::new();
    for index in 0..5 {
        let address = format!("person{index}@example.com");
        let user = created(
            storage
                .users
                .register(&acme, &email(&address), Timestamp::from_unix_secs(100))
                .await
                .expect("registered"),
        );
        registered.push((user, address));
    }
    registered.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
    let mut listed = Vec::new();
    let mut after: Option<UserId> = None;
    loop {
        let page = storage
            .users
            .page(&acme, after.as_ref(), 2)
            .await
            .expect("a page");
        assert!(page.len() <= 2, "a page holds at most what was asked");
        let Some(last) = page.last() else { break };
        after = Some(last.user.clone());
        listed.extend(
            page.into_iter()
                .map(|account| (account.user, account.email.as_str().to_owned())),
        );
    }
    assert_eq!(
        listed, registered,
        "every account once, in id order, with its own address"
    );
    let capped = storage
        .users
        .page(&acme, None, 10_000)
        .await
        .expect("a page");
    assert_eq!(
        capped.len(),
        5,
        "an oversized request is served up to the cap"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_account_is_disabled_and_enabled_only_from_the_status_it_has() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let user = created(
        storage
            .users
            .register(
                &acme,
                &email("leaver@example.com"),
                Timestamp::from_unix_secs(100),
            )
            .await
            .expect("registered"),
    );
    let users = &storage.users;
    let status = |found: Option<UserAccount>| found.expect("the account").status;
    assert_eq!(
        users
            .set_status(&acme, &user, UserStatus::Active, UserStatus::Disabled)
            .await,
        Ok(true)
    );
    assert_eq!(
        status(users.find(&acme, &user).await.expect("an answer")),
        UserStatus::Disabled
    );
    assert_eq!(
        users
            .set_status(&acme, &user, UserStatus::Active, UserStatus::Disabled)
            .await,
        Ok(false),
        "already disabled: nothing changes"
    );
    assert_eq!(
        users
            .set_status(&acme, &user, UserStatus::Disabled, UserStatus::Active)
            .await,
        Ok(true)
    );
    assert_eq!(
        status(users.find(&acme, &user).await.expect("an answer")),
        UserStatus::Active
    );
    let nobody = UserId::parse("nobody-at-all").expect("a user id");
    assert_eq!(
        users
            .set_status(&acme, &nobody, UserStatus::Active, UserStatus::Disabled)
            .await,
        Ok(false),
        "no such account: nothing changes"
    );
}
