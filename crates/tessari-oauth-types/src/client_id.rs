//! A client's id, as it arrives in `client_id` (RFC 6749 §2.2) and leaves in a token's `aud` or `azp`.

use tessari_oauth_constants::CLIENT_ID_MAX_LEN;

use crate::{Error, Result};

/// A client id: 1 to 255 visible ASCII characters or spaces (RFC 6749 Appendix A.1, `VSCHAR`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(String);

impl ClientId {
    /// Read a client id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `client_id` when the value is empty, longer than 255 bytes, or holds a
    /// character outside `%x20-7E` — a control character in an id is how a log line or a header gets split.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        let within_length = (1..=CLIENT_ID_MAX_LEN).contains(&raw.len());
        let visible = raw.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
        if !(within_length && visible) {
            return Err(Error::Invalid {
                field: "client_id",
                reason: "1 to 255 visible ASCII characters or spaces",
            });
        }
        Ok(Self(raw))
    }

    /// The id as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "client_id_tests.rs"]
mod tests;
