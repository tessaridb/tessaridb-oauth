//! A key-encryption key for tests, read from an owner-only file the way the server reads its own.

use std::os::unix::fs::PermissionsExt;

use tessari_oauth_infrastructure::custody::Kek;

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
