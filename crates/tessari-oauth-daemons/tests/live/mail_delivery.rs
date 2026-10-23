//! Mail delivery: a run hands each queued mail to the sender once and finishes it, drops a mail queued for no account
//! unsent, and keeps a mail the sender did not take for a later try.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tessari_oauth_daemons::{Daemon, MailDelivery, MailSender};
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_infrastructure::mail::OutgoingMail;
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::companies::Served;
use tessari_oauth_storage::outbox::NewMail;
use tessari_oauth_types::{EmailAddress, TenantId};

use crate::{fresh_kek, storage};

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn served() -> Arc<Served> {
    let served = Served::new("https://id.example.com");
    served.replace([acme()]);
    Arc::new(served)
}

/// A sender that records the `(to, subject, text)` of every mail it is handed and answers `takes`.
struct Recorder {
    takes: bool,
    sent: Mutex<Vec<(String, String, String)>>,
}

impl Recorder {
    fn new(takes: bool) -> Arc<Self> {
        Arc::new(Self {
            takes,
            sent: Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> Vec<(String, String, String)> {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        sent.sort();
        sent
    }
}

impl MailSender for Recorder {
    fn send<'a>(
        &'a self,
        mail: &'a OutgoingMail,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        // A short synchronous section; the guard is dropped before the future is returned.
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((
                mail.to.as_str().to_owned(),
                mail.subject.clone(),
                mail.text.clone(),
            ));
        let takes = self.takes;
        Box::pin(async move { takes })
    }
}

fn daemon(storage: &Storage, kek: &Arc<Kek>, sender: Arc<dyn MailSender>) -> MailDelivery {
    MailDelivery {
        outbox: Arc::clone(&storage.outbox),
        kek: Arc::clone(kek),
        served: served(),
        sender,
        interval: Duration::from_secs(5),
        timeout: Duration::from_secs(45),
    }
}

async fn queue(storage: &Storage, kek: &Kek, to: Option<&str>, subject: &str) {
    storage
        .outbox
        .enqueue(
            &acme(),
            kek,
            &NewMail {
                to: to.map(|address| EmailAddress::parse(address).expect("an address")),
                subject: subject.to_owned(),
                text: format!("{subject} text"),
            },
        )
        .await
        .expect("queued");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_run_sends_each_mail_once_and_drops_one_for_no_account() {
    let storage = storage();
    storage
        .tenants
        .provision(&acme())
        .await
        .expect("provisioned");
    let kek = fresh_kek();
    queue(&storage, &kek, Some("ada@example.com"), "Reset").await;
    queue(&storage, &kek, Some("bob@example.com"), "Verify").await;
    queue(&storage, &kek, None, "Reset").await;
    // Learn the ids by claiming, then release every mail at once for the run to take.
    let ids: Vec<String> = storage
        .outbox
        .claim(&acme(), &kek, 10)
        .await
        .expect("claimed")
        .into_iter()
        .map(|mail| mail.id)
        .collect();
    assert_eq!(ids.len(), 3);
    for id in &ids {
        storage
            .outbox
            .retry(&acme(), id, 0)
            .await
            .expect("released");
    }
    let recorder = Recorder::new(true);

    let report = daemon(&storage, &kek, recorder.clone())
        .run_once()
        .await
        .expect("a run");

    assert_eq!(
        recorder.sent(),
        vec![
            (
                "ada@example.com".to_owned(),
                "Reset".to_owned(),
                "Reset text".to_owned()
            ),
            (
                "bob@example.com".to_owned(),
                "Verify".to_owned(),
                "Verify text".to_owned()
            ),
        ]
    );
    assert_eq!(
        report.message,
        "tenants=1 sent=2 unsent=0 dropped=1 retried=0 abandoned=0"
    );
    for id in &ids {
        assert_eq!(
            storage.outbox.finish(&acme(), id).await,
            Ok(false),
            "the run deleted every mail it handled"
        );
    }
    let again = daemon(&storage, &kek, recorder.clone())
        .run_once()
        .await
        .expect("a run");
    assert_eq!(recorder.sent().len(), 2, "sent once");
    assert_eq!(
        again.message,
        "tenants=1 sent=0 unsent=0 dropped=0 retried=0 abandoned=0"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_mail_the_sender_did_not_take_is_kept_for_a_later_try() {
    let storage = storage();
    storage
        .tenants
        .provision(&acme())
        .await
        .expect("provisioned");
    let kek = fresh_kek();
    queue(&storage, &kek, Some("ada@example.com"), "Reset").await;
    let refusing = Recorder::new(false);

    let report = daemon(&storage, &kek, refusing.clone())
        .run_once()
        .await
        .expect("a run");

    assert_eq!(refusing.sent().len(), 1);
    assert_eq!(
        report.message,
        "tenants=1 sent=0 unsent=1 dropped=0 retried=1 abandoned=0"
    );
    let taking = Recorder::new(true);
    let soon = daemon(&storage, &kek, taking.clone())
        .run_once()
        .await
        .expect("a run");
    assert!(taking.sent().is_empty(), "not due before its delay");
    assert_eq!(
        soon.message,
        "tenants=1 sent=0 unsent=0 dropped=0 retried=0 abandoned=0"
    );
}
