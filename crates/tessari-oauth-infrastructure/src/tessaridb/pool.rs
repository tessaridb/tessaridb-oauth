//! A bounded set of signed-in connections, and the one way work reaches the store through them.
//!
//! A connection is a session: it holds the identity it signed in with and whatever `USE` it was last given. The
//! identity is worth keeping — a password costs an Argon2id verification, so it is spent once per connection —
//! and the `USE` is not, so every unit of work carries its own. A connection that failed is dropped rather than
//! handed to the next caller in an unknown state.

use std::sync::{Arc, Mutex, PoisonError};

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
        let (mut client, signing_in) = match reused {
            Some(client) => (client, false),
            None => (self.connect().await?, true),
        };
        let config = &self.inner.config;
        let credentials = signing_in.then_some((config.user.as_str(), config.password.as_str()));
        match client.run_with(&script, credentials, parameters).await {
            Ok(answers) => {
                self.release(client);
                Ok(answers.into_iter().skip(preamble).collect())
            }
            Err(tessaridb_client::Error::Refused { message, class }) => {
                // A refused statement leaves the session intact, unless the refusal was the sign-in itself.
                if class != Some(RefusalClass::Unauthenticated) {
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
