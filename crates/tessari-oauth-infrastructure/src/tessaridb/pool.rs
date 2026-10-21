//! A bounded set of signed-in connections, and the one way work reaches the store through them.
//!
//! A connection is a session: it holds the identity it signed in with and whatever `USE` it was last given. The
//! identity is worth keeping — a password costs an Argon2id verification, so it is spent once per connection —
//! and the `USE` is not, so every unit of work carries its own. A connection that failed is dropped rather than
//! handed to the next caller in an unknown state, and so is a new connection whose sign-in may not have happened:
//! reused, it would send work with no credentials and no session behind it.
//!
//! The node verifies only so many passwords at once and answers `throttled` beyond that, so new connections sign
//! in a few at a time and a throttled sign-in is tried again, bounded.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tessari_oauth_constants::{
    STORE_RETRY_FIRST_PAUSE_MS, STORE_RETRY_MAX_PAUSE_MS, STORE_SIGNIN_ATTEMPTS,
    STORE_SIGNIN_CONCURRENCY,
};
use tessaridb_client::{Answer, Client, RefusalClass, Value};
use tokio::sync::Semaphore;

use super::{Place, StoreConfig};
use crate::{Error, Result};

/// A handle on the store; cheap to clone, shared by every caller.
#[derive(Clone)]
pub struct Database {
    inner: Arc<Inner>,
}

struct Inner {
    config: StoreConfig,
    idle: Mutex<Vec<Client>>,
    slots: Semaphore,
    signins: Semaphore,
}

impl Database {
    /// A pool of at most `connections` connections to the store `config` names. Nothing connects until used.
    #[must_use]
    pub fn new(config: StoreConfig, connections: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                idle: Mutex::new(Vec::new()),
                slots: Semaphore::new(connections),
                signins: Semaphore::new(STORE_SIGNIN_CONCURRENCY),
            }),
        }
    }

    /// Run `script` at `place` with its values bound, answering one [`Answer`] per statement of `script`.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] with the node's own words, or [`Error::Unavailable`] when the store cannot be reached.
    pub async fn run_at(
        &self,
        place: &Place,
        script: &str,
        parameters: Vec<(String, Value)>,
    ) -> Result<Vec<Answer>> {
        let preamble = place.preamble();
        self.exchange(format!("{preamble} {script}"), parameters, 2)
            .await
    }

    /// Run `script` with no place selected — for provisioning, whose statements name their own places.
    ///
    /// # Errors
    ///
    /// As [`Database::run_at`].
    pub async fn run_unplaced(
        &self,
        script: &str,
        parameters: Vec<(String, Value)>,
    ) -> Result<Vec<Answer>> {
        self.exchange(script.to_owned(), parameters, 0).await
    }

    async fn exchange(
        &self,
        script: String,
        parameters: Vec<(String, Value)>,
        preamble: usize,
    ) -> Result<Vec<Answer>> {
        let _slot = self
            .inner
            .slots
            .acquire()
            .await
            .map_err(|_| Error::Unavailable {
                message: "the connection pool is closed".to_owned(),
            })?;
        let reused = self
            .inner
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        if let Some(client) = reused {
            return self
                .send(client, false, &script, parameters, preamble)
                .await;
        }
        let mut pause = Duration::from_millis(STORE_RETRY_FIRST_PAUSE_MS);
        let longest = Duration::from_millis(STORE_RETRY_MAX_PAUSE_MS);
        let mut made = 1;
        loop {
            let signing = self
                .inner
                .signins
                .acquire()
                .await
                .map_err(|_| Error::Unavailable {
                    message: "the connection pool is closed".to_owned(),
                })?;
            let client = self.connect().await?;
            let outcome = self
                .send(client, true, &script, parameters.clone(), preamble)
                .await;
            drop(signing);
            let throttled = matches!(
                &outcome,
                Err(Error::Refused {
                    class: Some(RefusalClass::Throttled),
                    ..
                })
            );
            if !throttled || made >= STORE_SIGNIN_ATTEMPTS {
                return outcome;
            }
            tokio::time::sleep(pause).await;
            pause = pause.saturating_mul(2).min(longest);
            made = made.saturating_add(1);
        }
    }

    /// Send one request on `client`, signing in first when `signing_in`, and keep the connection only when its
    /// session is certainly intact.
    async fn send(
        &self,
        mut client: Client,
        signing_in: bool,
        script: &str,
        parameters: Vec<(String, Value)>,
        preamble: usize,
    ) -> Result<Vec<Answer>> {
        let config = &self.inner.config;
        let credentials = signing_in.then_some((config.user.as_str(), config.password.as_str()));
        match client.run_with(script, credentials, parameters).await {
            Ok(answers) => {
                self.release(client);
                Ok(answers.into_iter().skip(preamble).collect())
            }
            Err(tessaridb_client::Error::Refused { message, class }) => {
                // A refused statement leaves the session intact — unless the refusal was about the session itself,
                // or was a sign-in the node did not take, which leaves a connection that never signed in.
                let session_lost = class == Some(RefusalClass::Unauthenticated)
                    || (signing_in && class == Some(RefusalClass::Throttled));
                if !session_lost {
                    self.release(client);
                }
                Err(Error::Refused { message, class })
            }
            Err(failure) => Err(Error::Unavailable {
                message: failure.to_string(),
            }),
        }
    }

    async fn connect(&self) -> Result<Client> {
        let address = &self.inner.config.address;
        let client =
            Client::connect(address.as_str())
                .await
                .map_err(|failure| Error::Unavailable {
                    message: failure.to_string(),
                })?;
        tracing::debug!(%address, "store connection opened");
        Ok(client)
    }

    fn release(&self, client: Client) {
        self.inner
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(client);
    }
}
