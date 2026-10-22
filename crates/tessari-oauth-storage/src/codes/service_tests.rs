use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Place, RefusalClass};
use tessari_oauth_types::{AuthorizationCode, TenantId, Timestamp};

use super::{CodeService, Consumed};
use crate::codes::CodeEntity;
use crate::codes::repository::CodeRepository;
use crate::{Error, Result, Tenancy};

/// A spend that fails without the store refusing it, over a record that reads as already spent.
struct FailingSpend;

fn spent_row() -> CodeEntity {
    CodeEntity {
        tenant: "acme-eu".to_owned(),
        client_id: "portal".to_owned(),
        user_id: "user-7".to_owned(),
        redirect_uri: "https://portal.example.com/callback".to_owned(),
        challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
        scopes: vec!["openid".to_owned()],
        resources: vec!["https://api.example.com/orders".to_owned()],
        expires_at: 1_800_000_060,
        auth_time: 1_800_000_000,
        methods: vec!["pwd".to_owned()],
        sid: "c2Vzc2lvbi1wdWJsaWMtaWQ".to_owned(),
        nonce: None,
        redeemed_at: Some(1_800_000_000),
    }
}

fn unreadable() -> Error {
    Error::Unreadable {
        record: "code",
        reason: "fixture".to_owned(),
    }
}

#[async_trait]
impl CodeRepository for FailingSpend {
    async fn create(&self, _place: &Place, _digest: &str, _code: &CodeEntity) -> Result<()> {
        Ok(())
    }

    async fn find(&self, _place: &Place, _digest: &str) -> Result<Option<CodeEntity>> {
        Ok(Some(spent_row()))
    }

    async fn mark_redeemed(
        &self,
        _place: &Place,
        _digest: &str,
        _at: i64,
    ) -> Result<Option<CodeEntity>> {
        Err(unreadable())
    }
}

/// A spend the store asks to be tried again once — what a loser sees while the winner's commit is still landing.
struct RetriedSpend {
    asked: AtomicUsize,
}

#[async_trait]
impl CodeRepository for RetriedSpend {
    async fn create(&self, _place: &Place, _digest: &str, _code: &CodeEntity) -> Result<()> {
        Ok(())
    }

    async fn find(&self, _place: &Place, _digest: &str) -> Result<Option<CodeEntity>> {
        Ok(Some(CodeEntity {
            redeemed_at: None,
            ..spent_row()
        }))
    }

    async fn mark_redeemed(
        &self,
        _place: &Place,
        _digest: &str,
        _at: i64,
    ) -> Result<Option<CodeEntity>> {
        if self.asked.fetch_add(1, Ordering::Relaxed) == 0 {
            return Err(Error::Store(tessari_oauth_infrastructure::Error::Refused {
                message: "write conflict".to_owned(),
                class: Some(RefusalClass::Retry),
            }));
        }
        Ok(Some(CodeEntity {
            redeemed_at: None,
            ..spent_row()
        }))
    }
}

#[tokio::test]
async fn a_spend_the_store_asks_to_retry_is_tried_again_rather_than_answered_from_a_read() {
    let repository = Arc::new(RetriedSpend {
        asked: AtomicUsize::new(0),
    });
    let service = CodeService::new(
        repository.clone(),
        Tenancy::for_region("eu").expect("plain region"),
    );
    let tenant = TenantId::parse("acme-eu").expect("a tenant id");
    let code = AuthorizationCode::from_secret("fixture-code-secret");

    let outcome = service
        .consume(&tenant, &code, Timestamp::from_unix_secs(1_800_000_000))
        .await;
    assert!(
        matches!(outcome, Ok(Consumed::Fresh(_))),
        "the second attempt spends the code: {outcome:?}"
    );
    assert_eq!(
        repository.asked.load(Ordering::Relaxed),
        2,
        "the spend was asked twice"
    );
}

#[tokio::test]
async fn a_spend_that_fails_without_a_refusal_is_reported_as_the_failure_and_never_as_a_replay() {
    let service = CodeService::new(
        Arc::new(FailingSpend),
        Tenancy::for_region("eu").expect("plain region"),
    );
    let tenant = TenantId::parse("acme-eu").expect("a tenant id");
    let code = AuthorizationCode::from_secret("fixture-code-secret");

    let outcome = service
        .consume(&tenant, &code, Timestamp::from_unix_secs(1_800_000_000))
        .await;
    assert_eq!(
        outcome,
        Err(unreadable()),
        "only the store refusing the spend may be answered by re-reading"
    );
}
