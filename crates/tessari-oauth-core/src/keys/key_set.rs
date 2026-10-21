//! The key set a tenant publishes (RFC 7517 §5): exactly the keys the rotation rule publishes, in its order.
//!
//! The stored public halves are already JSON and are embedded as they are, never parsed into a tree and written
//! again. A key the rule does not publish — retired, or withdrawn as compromised — cannot appear, because the set is
//! built from the rule's list rather than from the stored rows.

use serde::Serialize;
use serde_json::value::RawValue;
use tessari_oauth_types::KeyThumbprint;

use super::KeyPlan;

/// Why no key set could be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeySetError {
    /// A key the rule publishes has no stored public half.
    #[error("a published key has no stored public half")]
    MissingKey,
    /// A stored public half is not a JSON object.
    #[error("a stored public half is not a JSON object")]
    NotAKey,
}

#[derive(Serialize)]
struct KeySet<'a> {
    keys: Vec<&'a RawValue>,
}

/// The key set for `plan`, taking each published key's public JWK from `stored` (`kid` → JWK).
///
/// # Errors
///
/// [`KeySetError::MissingKey`] when a published key is absent from `stored`; [`KeySetError::NotAKey`] when its JWK
/// is not a JSON object.
pub fn key_set<'a>(
    plan: &KeyPlan,
    stored: impl IntoIterator<Item = (&'a KeyThumbprint, &'a str)>,
) -> Result<String, KeySetError> {
    let stored: Vec<(&KeyThumbprint, &str)> = stored.into_iter().collect();
    let mut keys = Vec::with_capacity(plan.published.len());
    for kid in &plan.published {
        let (_, jwk) = stored
            .iter()
            .find(|(candidate, _)| *candidate == kid)
            .ok_or(KeySetError::MissingKey)?;
        // Valid JSON is not enough: the set's members are objects.
        if !jwk.starts_with('{') {
            return Err(KeySetError::NotAKey);
        }
        let raw: &RawValue = serde_json::from_str(jwk).map_err(|_| KeySetError::NotAKey)?;
        keys.push(raw);
    }
    serde_json::to_string(&KeySet { keys }).map_err(|_| KeySetError::NotAKey)
}

#[cfg(test)]
#[path = "key_set_tests.rs"]
mod tests;
