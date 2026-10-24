//! The client data a browser signs over: which ceremony, which challenge, which origin (Web Authentication Level 3,
//! §5.8.1). The origin is what makes a passkey phishing-resistant, so it is matched exactly against the relying
//! party's own list.

use serde::Deserialize;
use subtle::ConstantTimeEq as _;
use tessari_oauth_types::base64url;

use super::{Expected, WebauthnRefused};

/// The fields a check reads; anything else the browser adds is ignored.
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ceremony: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

/// Check client data for `ceremony` (`webauthn.create` or `webauthn.get`) against `expected`.
pub(super) fn check(
    json: &[u8],
    ceremony: &str,
    expected: &Expected<'_>,
) -> Result<(), WebauthnRefused> {
    let data: ClientData =
        serde_json::from_slice(json).map_err(|_| WebauthnRefused::ClientDataUnreadable)?;
    if data.ceremony != ceremony {
        return Err(WebauthnRefused::WrongCeremony);
    }
    let challenge =
        base64url::decode(&data.challenge).map_err(|_| WebauthnRefused::ChallengeMismatch)?;
    if !bool::from(challenge.ct_eq(expected.challenge)) {
        return Err(WebauthnRefused::ChallengeMismatch);
    }
    if !expected.origins.contains(&data.origin.as_str()) {
        return Err(WebauthnRefused::OriginNotAllowed);
    }
    if data.cross_origin {
        return Err(WebauthnRefused::CrossOrigin);
    }
    Ok(())
}

/// The challenge `json` names, when it is client data at all.
pub(super) fn challenge(json: &[u8]) -> Option<Vec<u8>> {
    let data: ClientData = serde_json::from_slice(json).ok()?;
    base64url::decode(&data.challenge).ok()
}

#[cfg(test)]
#[path = "client_data_tests.rs"]
mod tests;
