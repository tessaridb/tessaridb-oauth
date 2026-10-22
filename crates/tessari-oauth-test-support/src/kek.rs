//! A key-encryption key and a password pepper for tests, each read from an owner-only file the way the server reads
//! its own.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use tessari_oauth_infrastructure::custody::{Kek, PasswordCost, Passwords};

use crate::{Error, unique};

/// A key-encryption key read from a fresh owner-only file, which is removed once read.
///
/// # Errors
///
/// When the file cannot be written, restricted or removed, or the key it holds is refused.
pub fn fresh_kek() -> Result<Kek, Error> {
    let path = std::env::temp_dir().join(unique("kek"));
    let bytes: Vec<u8> = (0_u8..32).collect();
    std::fs::write(&path, bytes).map_err(Error::KeyFile)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(Error::KeyFile)?;
    let kek = Kek::load(&path).map_err(Error::Kek)?;
    std::fs::remove_file(&path).map_err(Error::KeyFile)?;
    Ok(kek)
}

/// Password hashing at `cost`, two at a time, under a pepper read from a fresh owner-only file, which is removed once
/// read.
///
/// # Errors
///
/// When the file cannot be written, restricted or removed, or the pepper it holds is refused.
pub fn fresh_passwords(cost: PasswordCost) -> Result<Arc<Passwords>, Error> {
    let path = std::env::temp_dir().join(unique("pepper"));
    let bytes: Vec<u8> = (32_u8..64).collect();
    std::fs::write(&path, bytes).map_err(Error::KeyFile)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(Error::KeyFile)?;
    let passwords = Passwords::load(&path, cost, 2).map_err(Error::Pepper)?;
    std::fs::remove_file(&path).map_err(Error::KeyFile)?;
    Ok(passwords)
}
