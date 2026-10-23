use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tessari_oauth_storage::companies::Elsewhere;
use tessari_oauth_types::TenantId;

use super::{Peer, PeerDirectories, PeerDirectory, PeerHomes};
use crate::daemon::Daemon;

const EU: &str = "https://eu.id.example.com";
const US: &str = "https://us.id.example.com";

fn company(id: &str) -> TenantId {
    TenantId::parse(id).expect("a company id")
}

/// A peer region whose next answer the test sets: its homes, or a failure when `None`.
struct Fake {
    answer: Mutex<Option<PeerHomes>>,
}

impl Fake {
    fn new(base: Option<&str>, companies: &[&str]) -> Arc<Self> {
        let fake = Arc::new(Self {
            answer: Mutex::new(None),
        });
        fake.answer_with(base, companies);
        fake
    }

    fn answer_with(&self, base: Option<&str>, companies: &[&str]) {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = Some(PeerHomes {
            base: base.map(Arc::from),
            companies: companies.iter().map(|id| company(id)).collect(),
        });
    }

    fn fail(&self) {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl PeerDirectory for Fake {
    fn read(
        &self,
    ) -> Pin<Box<dyn Future<Output = tessari_oauth_storage::Result<PeerHomes>> + Send + '_>> {
        let answer = self
            .answer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Box::pin(async move {
            answer.ok_or(tessari_oauth_storage::Error::Unreadable {
                record: "company",
                reason: "the peer did not answer".to_owned(),
            })
        })
    }
}

fn daemon(peers: &[(&str, &Arc<Fake>)], elsewhere: &Arc<Elsewhere>) -> PeerDirectories {
    let peers = peers
        .iter()
        .map(|(region, fake)| Peer {
            region: (*region).to_owned(),
            directory: Arc::clone(*fake) as Arc<dyn PeerDirectory>,
        })
        .collect();
    PeerDirectories::new(
        peers,
        Arc::clone(elsewhere),
        Duration::from_secs(5),
        Duration::from_secs(4),
    )
}

#[tokio::test]
async fn every_peers_companies_are_found_at_their_regions_base() {
    let elsewhere = Arc::new(Elsewhere::new());
    let eu = Fake::new(Some(EU), &["acme", "globex"]);
    let us = Fake::new(Some(US), &["beta"]);
    let report = daemon(&[("eu", &eu), ("us", &us)], &elsewhere)
        .run_once()
        .await
        .expect("a run");
    assert_eq!(report.message, "peers=2 answered=2 companies=3");
    assert_eq!(elsewhere.home(&company("acme")).as_deref(), Some(EU));
    assert_eq!(elsewhere.home(&company("globex")).as_deref(), Some(EU));
    assert_eq!(elsewhere.home(&company("beta")).as_deref(), Some(US));
    assert_eq!(elsewhere.home(&company("gamma")), None);
}

#[tokio::test]
async fn a_peer_that_does_not_answer_keeps_what_it_last_said() {
    let elsewhere = Arc::new(Elsewhere::new());
    let eu = Fake::new(Some(EU), &["acme"]);
    let us = Fake::new(Some(US), &["beta"]);
    let peers = daemon(&[("eu", &eu), ("us", &us)], &elsewhere);
    peers.run_once().await.expect("a run");
    eu.fail();
    us.answer_with(Some(US), &["delta"]);
    let report = peers.run_once().await.expect("a run");
    assert_eq!(report.message, "peers=2 answered=1 companies=2");
    assert_eq!(
        elsewhere.home(&company("acme")).as_deref(),
        Some(EU),
        "kept"
    );
    assert_eq!(
        elsewhere.home(&company("delta")).as_deref(),
        Some(US),
        "read"
    );
    assert_eq!(
        elsewhere.home(&company("beta")),
        None,
        "no longer served there"
    );
}

#[tokio::test]
async fn a_peer_with_no_base_url_sends_nobody_there() {
    let elsewhere = Arc::new(Elsewhere::new());
    let eu = Fake::new(None, &["acme"]);
    let report = daemon(&[("eu", &eu)], &elsewhere)
        .run_once()
        .await
        .expect("a run");
    assert_eq!(report.message, "peers=1 answered=1 companies=0");
    assert_eq!(elsewhere.home(&company("acme")), None);
}

#[tokio::test]
async fn a_company_two_peers_name_is_sent_to_the_first() {
    let elsewhere = Arc::new(Elsewhere::new());
    let eu = Fake::new(Some(EU), &["acme"]);
    let us = Fake::new(Some(US), &["acme"]);
    daemon(&[("eu", &eu), ("us", &us)], &elsewhere)
        .run_once()
        .await
        .expect("a run");
    assert_eq!(elsewhere.home(&company("acme")).as_deref(), Some(EU));
}
