//! Consent as the protocol core sees it: whether a request is inside a grant, and the delta when it is not.

mod coverage;

pub use coverage::{ConsentRequest, Coverage, GrantedConsent, coverage};
