//! Every number and fixed alphabet with a meaning in TessariDB OAuth, typed and documented with its unit
//! and the specification it comes from.

mod encoding;
mod ids;
mod pkce;
mod storage;

pub use encoding::{BASE64URL_ALPHABET, SHA256_BASE64URL_LEN};
pub use ids::{CLIENT_ID_MAX_LEN, TENANT_ID_MAX_LEN, USER_ID_MAX_LEN};
pub use pkce::{AUTHORIZATION_CODE_TTL_SECS, PKCE_VERIFIER_MAX_LEN, PKCE_VERIFIER_MIN_LEN};
pub use storage::{
    CODE_SPEND_ATTEMPTS, CONSENT_WRITE_ATTEMPTS, STORE_RETRY_FIRST_PAUSE_MS,
    STORE_RETRY_MAX_PAUSE_MS, STORE_SIGNIN_ATTEMPTS, STORE_SIGNIN_CONCURRENCY,
};
