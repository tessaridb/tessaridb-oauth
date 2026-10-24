//! Verifying a compact JWS (RFC 7515 §7.1) in the order that keeps the object from choosing its own verification:
//! shape, then the header against configuration, then the key, then the signature.
//!
//! Two ways to find the key, never mixed: [`verify`] chooses among keys registered beforehand and ignores any key the
//! object carries; [`verify_embedded`] takes the key the object carries (a DPoP proof is self-describing), which is
//! only safe because the caller then binds the token to that key's thumbprint rather than trusting the key.

use serde::Deserialize;
use serde_json::value::RawValue;
use tessari_oauth_types::base64url;

use super::{Algorithm, JoseError, VerifyingKey};

/// The header members read here. Key locations (`jku`, `x5u`, `x5c`) are never read; `jwk` is read only by
/// [`verify_embedded`], kept as the slice it arrived as for the key reader to parse once.
#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    typ: Option<String>,
    crit: Option<serde::de::IgnoredAny>,
    jwk: Option<Box<RawValue>>,
}

/// A JWS whose signature verified: its declared type, for the caller to judge, and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The `typ` header, when present.
    pub typ: Option<String>,
    /// The decoded payload.
    pub payload: Vec<u8>,
}

/// A compact JWS split and decoded, its signature not yet checked.
struct Parts<'a> {
    header: Header,
    payload: Vec<u8>,
    signature: Vec<u8>,
    /// The two encoded segments exactly as presented (RFC 7515 §5.2 step 8).
    signing_input: &'a str,
}

/// Split `compact` into exactly three base64url segments and read its header.
fn parts(compact: &str) -> Result<Parts<'_>, JoseError> {
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
    if header.crit.is_some() {
        return Err(JoseError::CriticalHeader);
    }
    let signing_input = compact
        .rsplit_once('.')
        .map(|(input, _)| input)
        .ok_or(JoseError::Malformed)?;
    Ok(Parts {
        header,
        payload: decoded(payload)?,
        signature: decoded(signature)?,
        signing_input,
    })
}

/// The verified result of `parts` under `key`.
fn checked(parts: Parts<'_>, key: &VerifyingKey) -> Result<Verified, JoseError> {
    if !key.verifies(parts.signing_input.as_bytes(), &parts.signature) {
        return Err(JoseError::BadSignature);
    }
    Ok(Verified {
        typ: parts.header.typ,
        payload: parts.payload,
    })
}

/// Verify `compact` under `algorithm` with one of `keys`, and return its type and payload.
///
/// # Errors
///
/// [`JoseError::Malformed`] for anything but three base64url segments with a JSON-object header;
/// [`JoseError::CriticalHeader`] when it carries `crit`; [`JoseError::AlgorithmNotAllowed`] when the header's `alg`
/// is not `algorithm`; [`JoseError::UnknownKey`] when no single registered key of `algorithm` is selected;
/// [`JoseError::BadSignature`] when the signature does not verify.
pub fn verify(
    compact: &str,
    algorithm: Algorithm,
    keys: &[VerifyingKey],
) -> Result<Verified, JoseError> {
    let parts = parts(compact)?;
    if parts.header.alg != algorithm.name() {
        return Err(JoseError::AlgorithmNotAllowed);
    }
    let key = select(keys, algorithm, parts.header.kid.as_deref())?;
    checked(parts, key)
}

/// Verify `compact` with the public key its own `jwk` header carries, under one of the `allowed` algorithms, and
/// return the result with that key.
///
/// # Errors
///
/// As [`verify`], except that the key is the header's: [`JoseError::KeyRefused`] when `jwk` is absent or is not a
/// public signing key of the header's algorithm, and [`JoseError::AlgorithmNotAllowed`] for an `alg` outside
/// `allowed`.
pub fn verify_embedded(
    compact: &str,
    allowed: &[Algorithm],
) -> Result<(Verified, VerifyingKey), JoseError> {
    let parts = parts(compact)?;
    let algorithm = allowed
        .iter()
        .copied()
        .find(|algorithm| algorithm.name() == parts.header.alg)
        .ok_or(JoseError::AlgorithmNotAllowed)?;
    let jwk = parts.header.jwk.as_deref().ok_or(JoseError::KeyRefused)?;
    let key = VerifyingKey::from_jwk(jwk.get(), algorithm)?;
    let verified = checked(parts, &key)?;
    Ok((verified, key))
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
