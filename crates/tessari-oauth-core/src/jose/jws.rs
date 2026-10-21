//! Verifying a compact JWS (RFC 7515 §7.1) in the order that keeps the object from choosing its own verification:
//! shape, then the header against configuration, then the key among the registered ones, then the signature.

use serde::Deserialize;
use tessari_oauth_types::base64url;

use super::{Algorithm, JoseError, VerifyingKey};

/// The header members read here. Every other member is ignored, including keys and key locations (`jwk`, `jku`,
/// `x5u`, `x5c`), which are never a source of the verifying key.
#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    crit: Option<serde::de::IgnoredAny>,
}

/// Verify `compact` under `algorithm` with one of `keys`, and return its payload.
///
/// # Errors
///
/// [`JoseError::Malformed`] for anything but three base64url segments with a JSON-object header;
/// [`JoseError::AlgorithmNotAllowed`] when the header's `alg` is not `algorithm`; [`JoseError::CriticalHeader`]
/// when it carries `crit`; [`JoseError::UnknownKey`] when no single registered key of `algorithm` is selected;
/// [`JoseError::BadSignature`] when the signature does not verify.
pub fn verify(
    compact: &str,
    algorithm: Algorithm,
    keys: &[VerifyingKey],
) -> Result<Vec<u8>, JoseError> {
    let mut segments = compact.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(JoseError::Malformed);
    };
    let decoded = |segment: &str| base64url::decode(segment).map_err(|_| JoseError::Malformed);
    let header: Header =
        serde_json::from_slice(&decoded(header)?).map_err(|_| JoseError::Malformed)?;
    let payload_bytes = decoded(payload)?;
    let signature = decoded(signature)?;
    if header.alg != algorithm.name() {
        return Err(JoseError::AlgorithmNotAllowed);
    }
    if header.crit.is_some() {
        return Err(JoseError::CriticalHeader);
    }
    let key = select(keys, algorithm, header.kid.as_deref())?;
    // The signing input is the two encoded segments exactly as presented (RFC 7515 §5.2 step 8).
    let signing_input = compact
        .rsplit_once('.')
        .map(|(input, _)| input)
        .ok_or(JoseError::Malformed)?;
    if !key.verifies(signing_input.as_bytes(), &signature) {
        return Err(JoseError::BadSignature);
    }
    Ok(payload_bytes)
}

/// The one registered key of `algorithm` that `kid` names, or the only one when there is no `kid`.
fn select<'k>(
    keys: &'k [VerifyingKey],
    algorithm: Algorithm,
    kid: Option<&str>,
) -> Result<&'k VerifyingKey, JoseError> {
    let mut candidates = keys
        .iter()
        .filter(|key| key.algorithm() == algorithm && kid.is_none_or(|kid| key.kid() == Some(kid)));
    match (candidates.next(), candidates.next()) {
        (Some(key), None) => Ok(key),
        _ => Err(JoseError::UnknownKey),
    }
}

#[cfg(test)]
#[path = "jws_tests.rs"]
mod tests;
