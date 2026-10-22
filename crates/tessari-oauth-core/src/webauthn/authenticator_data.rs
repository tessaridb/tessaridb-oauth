//! Authenticator data: the relying-party id's hash, the flags, the signature counter and, at registration, the new
//! credential (Web Authentication Level 3, §6.1). Every length is read from the bytes and checked against what is
//! left, and nothing may follow the last declared part.

use coset::cbor::{self, Value};
use ring::digest::{SHA256, digest};
use subtle::ConstantTimeEq as _;
use tessari_oauth_constants::WEBAUTHN_CREDENTIAL_ID_MAX_BYTES;

use super::WebauthnRefused;

/// User present.
pub(super) const USER_PRESENT: u8 = 0x01;
/// User verified.
pub(super) const USER_VERIFIED: u8 = 0x04;
/// Backup eligible: the credential may be synced to other devices.
pub(super) const BACKUP_ELIGIBLE: u8 = 0x08;
/// Backed up.
const BACKED_UP: u8 = 0x10;
/// Attested credential data included.
const ATTESTED: u8 = 0x40;
/// Extension outputs included.
const EXTENSIONS: u8 = 0x80;

/// Bytes of the relying-party id's SHA-256 hash.
const RP_ID_HASH_BYTES: usize = 32;
/// Bytes of the authenticator model identifier ahead of the credential id.
const AAGUID_BYTES: usize = 16;

/// Authenticator data read and checked against its relying party.
pub(super) struct AuthenticatorData<'a> {
    pub(super) flags: u8,
    pub(super) sign_count: u32,
    pub(super) credential: Option<Credential<'a>>,
}

/// The credential a registration carries.
pub(super) struct Credential<'a> {
    pub(super) id: &'a [u8],
    /// The COSE key, exactly as the authenticator encoded it.
    pub(super) public_key: &'a [u8],
}

/// Read `data` and check it was made for `rp_id`.
pub(super) fn parse<'a>(
    data: &'a [u8],
    rp_id: &str,
) -> Result<AuthenticatorData<'a>, WebauthnRefused> {
    let unreadable = || WebauthnRefused::AuthenticatorDataUnreadable;
    let (rp_id_hash, rest) = data
        .split_at_checked(RP_ID_HASH_BYTES)
        .ok_or_else(unreadable)?;
    let (&flags, rest) = rest.split_first().ok_or_else(unreadable)?;
    let (count, mut rest) = rest.split_first_chunk::<4>().ok_or_else(unreadable)?;
    if !bool::from(rp_id_hash.ct_eq(digest(&SHA256, rp_id.as_bytes()).as_ref())) {
        return Err(WebauthnRefused::RpIdMismatch);
    }
    if flags & BACKED_UP != 0 && flags & BACKUP_ELIGIBLE == 0 {
        return Err(unreadable());
    }
    let credential = if flags & ATTESTED == 0 {
        None
    } else {
        let (_aaguid, after) = rest.split_at_checked(AAGUID_BYTES).ok_or_else(unreadable)?;
        let (length, after) = after.split_first_chunk::<2>().ok_or_else(unreadable)?;
        let length = usize::from(u16::from_be_bytes(*length));
        if length > WEBAUTHN_CREDENTIAL_ID_MAX_BYTES {
            return Err(unreadable());
        }
        let (id, after) = after.split_at_checked(length).ok_or_else(unreadable)?;
        let (public_key, after) = one_item(after).ok_or_else(unreadable)?;
        rest = after;
        Some(Credential { id, public_key })
    };
    if flags & EXTENSIONS != 0 {
        let (_extensions, after) = one_item(rest).ok_or_else(unreadable)?;
        rest = after;
    }
    if !rest.is_empty() {
        return Err(unreadable());
    }
    Ok(AuthenticatorData {
        flags,
        sign_count: u32::from_be_bytes(*count),
        credential,
    })
}

/// Split `bytes` after the one CBOR item they begin with, or none when they do not begin with one.
fn one_item(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut reader = bytes;
    let _: Value = cbor::de::from_reader(&mut reader).ok()?;
    bytes.split_at_checked(bytes.len().checked_sub(reader.len())?)
}
