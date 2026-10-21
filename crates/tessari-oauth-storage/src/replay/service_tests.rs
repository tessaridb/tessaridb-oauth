use tessari_oauth_constants::CLOCK_SKEW_SECS;
use tessari_oauth_core::assertion::AssertionUse;
use tessari_oauth_core::dpop::ProofUse;
use tessari_oauth_types::{ClientId, KeyThumbprint, Timestamp};

use super::{assertion_key, proof_key, remember_for};

const KEY: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

fn assertion(client: &str, jti: &str) -> AssertionUse {
    AssertionUse {
        client_id: ClientId::parse(client).expect("a client id"),
        jti: jti.to_owned(),
        expires_at: Timestamp::from_unix_secs(0),
    }
}

fn proof(jti: &str) -> ProofUse {
    ProofUse {
        thumbprint: KeyThumbprint::parse(KEY).expect("a thumbprint"),
        jti: jti.to_owned(),
        expires_at: Timestamp::from_unix_secs(0),
    }
}

#[test]
fn keys_name_their_kind_and_their_owner_unambiguously() {
    assert_eq!(assertion_key(&assertion("svc", "a-1")), "a:3:svc:a-1");
    assert_eq!(proof_key(&proof("p-1")), format!("p:{KEY}:p-1"));
    assert_ne!(
        assertion_key(&assertion("a b", "c")),
        assertion_key(&assertion("a", "b c"))
    );
    assert_ne!(
        assertion_key(&assertion("a:1", "x")),
        assertion_key(&assertion("a", "1:x"))
    );
    assert_ne!(
        assertion_key(&assertion(KEY, "p-1")),
        proof_key(&proof("p-1"))
    );
}

#[test]
fn a_record_outlives_what_it_records_by_the_skew_and_is_never_shorter_than_a_second() {
    let now = Timestamp::from_unix_secs(1_000);
    let at = Timestamp::from_unix_secs;
    assert_eq!(remember_for(at(1_060), now), 60 + CLOCK_SKEW_SECS);
    assert_eq!(remember_for(at(1_000), now), CLOCK_SKEW_SECS);
    assert_eq!(remember_for(at(0), now), 1);
}

mod when_the_store_does_not_answer {
    use std::sync::Arc;

    use async_trait::async_trait;
    use tessari_oauth_infrastructure::tessaridb::Place;
    use tessari_oauth_types::TenantId;

    use super::{KEY, assertion, proof};
    use crate::replay::ReplayService;
    use crate::replay::repository::ReplayRepository;
    use crate::{Error, Result, Tenancy};

    /// A backend that never answers.
    struct Down;

    #[async_trait]
    impl ReplayRepository for Down {
        async fn record_if_absent(&self, _: &Place, _: &str, _: u64) -> Result<bool> {
            Err(Error::Store(
                tessari_oauth_infrastructure::Error::Unavailable {
                    message: "the node is down".to_owned(),
                },
            ))
        }
    }

    #[tokio::test]
    async fn a_spend_fails_closed_rather_than_counting_as_fresh() {
        let service =
            ReplayService::new(Arc::new(Down), Tenancy::for_region("eu").expect("a region"));
        let tenant = TenantId::parse("acme").expect("a tenant");
        let now = tessari_oauth_types::Timestamp::from_unix_secs(0);
        assert!(
            service
                .spend_assertion(&tenant, &assertion(KEY, "j"), now)
                .await
                .is_err()
        );
        assert!(
            service
                .spend_proof(&tenant, &proof("j"), now)
                .await
                .is_err()
        );
    }
}
