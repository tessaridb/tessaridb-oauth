use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tessari_oauth_core::subject::pairwise;
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_infrastructure::tessaridb::{Place, RefusalClass};
use tessari_oauth_test_support::fresh_kek;
use tessari_oauth_types::{ClientId, TenantId, Timestamp, UserId, base64url};

use super::{PAIRWISE_SALT, SubjectService};
use crate::subjects::SecretEntity;
use crate::subjects::repository::SecretRepository;
use crate::{Error, Result, Tenancy};

/// The salt another request made first.
const WINNER: [u8; 32] = [5; 32];

/// A store where this request finds no salt, loses the write to another request, and then reads the winner's salt.
struct LostTheRace {
    sealed: SecretEntity,
    finds: AtomicUsize,
    creates: AtomicUsize,
}

#[async_trait]
impl SecretRepository for LostTheRace {
    async fn create(&self, _place: &Place, _purpose: &str, _secret: &SecretEntity) -> Result<()> {
        self.creates.fetch_add(1, Ordering::Relaxed);
        Err(Error::Store(tessari_oauth_infrastructure::Error::Refused {
            message: "a record exists under this id".to_owned(),
            class: Some(RefusalClass::Conflict),
        }))
    }

    async fn find(&self, _place: &Place, _purpose: &str) -> Result<Option<SecretEntity>> {
        let earlier = self.finds.fetch_add(1, Ordering::Relaxed);
        Ok((earlier > 0).then(|| self.sealed.clone()))
    }
}

#[tokio::test]
async fn a_request_that_loses_the_first_write_uses_the_salt_that_won() {
    let tenant = TenantId::parse("acme").expect("a tenant id");
    let kek: Kek = fresh_kek().expect("a key-encryption key");
    let repository = Arc::new(LostTheRace {
        sealed: SecretEntity {
            sealed: base64url::encode(&kek.seal(&tenant, PAIRWISE_SALT, &WINNER).expect("sealed")),
            created_at: 1_800_000_000,
        },
        finds: AtomicUsize::new(0),
        creates: AtomicUsize::new(0),
    });
    let service = SubjectService::new(
        repository.clone(),
        Tenancy::for_region("eu").expect("plain region"),
    );
    let (client, user) = (
        ClientId::parse("svc-1").expect("a client id"),
        UserId::parse("user-7").expect("a user id"),
    );
    let subject = service
        .pairwise(
            &tenant,
            &kek,
            &client,
            &user,
            Timestamp::from_unix_secs(1_800_000_001),
        )
        .await
        .expect("a subject");
    assert_eq!(subject, pairwise(&WINNER, &client, &user));
    assert_eq!(
        repository.creates.load(Ordering::Relaxed),
        1,
        "it tried to make one"
    );
}
