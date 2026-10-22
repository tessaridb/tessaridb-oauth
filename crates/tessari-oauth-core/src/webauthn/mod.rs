//! Passkeys: the relying party's half of Web Authentication Level 3 (W3C Recommendation, 2026-08-25).
//!
//! A passkey is phishing-resistant because the browser binds every response to the origin and the authenticator to
//! the relying-party id; that holds only if the server checks every field of every response, so each check here
//! refuses with its own reason. Registration reads a new credential's public key out of a `none` attestation —
//! nothing here needs to know which authenticator made it. An assertion is a signature, by that key, over the
//! authenticator data and the hash of the client data, which is what proves possession; the signature is verified by
//! `ring`, and only the parsing and the checks around it are this module's.

mod authenticator_data;
mod client_data;
mod key;

use coset::cbor::{self, Value};
use ring::digest::{SHA256, digest};
use tessari_oauth_constants::WEBAUTHN_PART_MAX_BYTES;

use authenticator_data::{BACKUP_ELIGIBLE, USER_PRESENT, USER_VERIFIED};

/// Why a passkey response was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebauthnRefused {
    /// A response part larger than any authenticator sends.
    #[error("a response part is too large")]
    TooLarge,
    /// The client data is not the JSON a browser sends.
    #[error("the client data is unreadable")]
    ClientDataUnreadable,
    /// The client data names another ceremony.
    #[error("the client data is for another ceremony")]
    WrongCeremony,
    /// The challenge is not the one this ceremony issued.
    #[error("the challenge does not match")]
    ChallengeMismatch,
    /// The origin is not one this relying party serves.
    #[error("the origin is not allowed")]
    OriginNotAllowed,
    /// The response was made inside a frame of another origin.
    #[error("the response was made cross-origin")]
    CrossOrigin,
    /// The authenticator data is not the layout the specification defines.
    #[error("the authenticator data is unreadable")]
    AuthenticatorDataUnreadable,
    /// The authenticator data is for another relying-party id.
    #[error("the relying-party id does not match")]
    RpIdMismatch,
    /// The user was not present.
    #[error("the user was not present")]
    UserNotPresent,
    /// User verification was required and not performed.
    #[error("the user was not verified")]
    UserNotVerified,
    /// The attestation object is not readable, or carries no credential.
    #[error("the attestation is unreadable")]
    AttestationUnreadable,
    /// The credential's public key is not a key this relying party accepts.
    #[error("the public key is not accepted")]
    KeyNotAccepted,
    /// The signature does not verify under the credential's key.
    #[error("the signature does not verify")]
    SignatureInvalid,
}

/// What a response is checked against: this relying party, and this ceremony's challenge.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The relying-party id the authenticator scoped the credential to.
    pub rp_id: &'a str,
    /// The origins this relying party serves.
    pub origins: &'a [&'a str],
    /// The challenge this ceremony issued.
    pub challenge: &'a [u8],
    /// Whether the user must have been verified (PIN, biometric), not only present.
    pub user_verification: bool,
}

/// A credential a registration produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The credential id the authenticator chose.
    pub credential_id: Vec<u8>,
    /// The public key, as the COSE key the authenticator sent.
    pub public_key: Vec<u8>,
    /// The signature counter at registration.
    pub sign_count: u32,
    /// Whether the user was verified.
    pub user_verified: bool,
    /// Whether the credential may be synced to other devices.
    pub backup_eligible: bool,
}

/// What a verified assertion proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asserted {
    /// The signature counter now.
    pub sign_count: u32,
    /// Whether the user was verified.
    pub user_verified: bool,
    /// A non-zero counter that did not move forward: the credential may have been cloned.
    pub clone_suspected: bool,
}

/// Check a registration response (`webauthn.create`) and read the credential out of it.
///
/// # Errors
///
/// The [`WebauthnRefused`] naming the first check that failed.
pub fn register(
    client_data_json: &[u8],
    attestation_object: &[u8],
    expected: &Expected<'_>,
) -> Result<Registered, WebauthnRefused> {
    within_limit(&[client_data_json, attestation_object])?;
    client_data::check(client_data_json, "webauthn.create", expected)?;
    let auth_data = attested_data(attestation_object)?;
    let data = authenticator_data::parse(&auth_data, expected.rp_id)?;
    presence(data.flags, expected)?;
    let credential = data
        .credential
        .ok_or(WebauthnRefused::AttestationUnreadable)?;
    key::parse(credential.public_key)?;
    Ok(Registered {
        credential_id: credential.id.to_vec(),
        public_key: credential.public_key.to_vec(),
        sign_count: data.sign_count,
        user_verified: data.flags & USER_VERIFIED != 0,
        backup_eligible: data.flags & BACKUP_ELIGIBLE != 0,
    })
}

/// Check an assertion (`webauthn.get`) by the credential whose COSE key is `public_key` and whose last counter was
/// `stored_count`.
///
/// # Errors
///
/// The [`WebauthnRefused`] naming the first check that failed.
pub fn assert(
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
    stored_count: u32,
    expected: &Expected<'_>,
) -> Result<Asserted, WebauthnRefused> {
    within_limit(&[client_data_json, authenticator_data, signature, public_key])?;
    client_data::check(client_data_json, "webauthn.get", expected)?;
    let data = authenticator_data::parse(authenticator_data, expected.rp_id)?;
    if data.credential.is_some() {
        return Err(WebauthnRefused::AuthenticatorDataUnreadable);
    }
    presence(data.flags, expected)?;
    let key = key::parse(public_key)?;
    let client_data_hash = digest(&SHA256, client_data_json);
    let mut message = Vec::with_capacity(
        authenticator_data
            .len()
            .saturating_add(client_data_hash.as_ref().len()),
    );
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(client_data_hash.as_ref());
    key.verify(&message, signature)?;
    let counted = data.sign_count != 0 || stored_count != 0;
    Ok(Asserted {
        sign_count: data.sign_count,
        user_verified: data.flags & USER_VERIFIED != 0,
        clone_suspected: counted && data.sign_count <= stored_count,
    })
}

/// The challenge an assertion's client data names, so the ceremony that issued it can be found; `None` for client
/// data that is unreadable or larger than any browser sends. Finding it proves nothing: [`assert`] checks it.
#[must_use]
pub fn challenge_of(client_data_json: &[u8]) -> Option<Vec<u8>> {
    within_limit(&[client_data_json]).ok()?;
    client_data::challenge(client_data_json)
}

/// Refuse a response part larger than any authenticator sends, before any of it is parsed.
fn within_limit(parts: &[&[u8]]) -> Result<(), WebauthnRefused> {
    if parts
        .iter()
        .any(|part| part.len() > WEBAUTHN_PART_MAX_BYTES)
    {
        return Err(WebauthnRefused::TooLarge);
    }
    Ok(())
}

/// Refuse authenticator data whose flags show the user absent, or unverified where verification is required.
fn presence(flags: u8, expected: &Expected<'_>) -> Result<(), WebauthnRefused> {
    if flags & USER_PRESENT == 0 {
        return Err(WebauthnRefused::UserNotPresent);
    }
    if expected.user_verification && flags & USER_VERIFIED == 0 {
        return Err(WebauthnRefused::UserNotVerified);
    }
    Ok(())
}

/// The authenticator data inside an attestation object (§6.5.4). The statement is not verified: this relying
/// party asks for `none` and needs no authenticator provenance, so whatever format arrives is read for its data.
fn attested_data(object: &[u8]) -> Result<Vec<u8>, WebauthnRefused> {
    let unreadable = || WebauthnRefused::AttestationUnreadable;
    let mut reader = object;
    let Ok(Value::Map(entries)) = cbor::de::from_reader::<Value, _>(&mut reader) else {
        return Err(unreadable());
    };
    if !reader.is_empty() {
        return Err(unreadable());
    }
    let mut format = None;
    let mut data = None;
    for (key, value) in entries {
        match (key.as_text(), value) {
            (Some("fmt"), Value::Text(name)) => format = Some(name),
            (Some("authData"), Value::Bytes(bytes)) => data = Some(bytes),
            _ => {}
        }
    }
    format.and(data).ok_or_else(unreadable)
}

#[cfg(test)]
mod authenticator;
#[cfg(test)]
#[path = "key_tests.rs"]
mod key_tests;
#[cfg(test)]
#[path = "layout_tests.rs"]
mod layout_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
