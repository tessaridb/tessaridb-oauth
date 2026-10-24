//! What `reseal` is asked to do, read from the words after the subcommand: the file of the key-encryption key the
//! store is sealed under now. The new key is the server's own, `TESSARIDB_OAUTH_KEK`.

use std::path::PathBuf;

use crate::{Error, Result};

/// The words `reseal` accepts after its name.
const USAGE: &str = "--old-kek <file>";

/// The file `arguments` name as the old key.
///
/// # Errors
///
/// [`Error::Invalid`] naming the usage for any other arrangement of words.
pub fn old_kek_path(arguments: &[String]) -> Result<PathBuf> {
    match arguments {
        [flag, path] if flag == "--old-kek" => Ok(PathBuf::from(path)),
        _ => Err(Error::Invalid {
            key: "arguments",
            value: arguments.join(" "),
            reason: USAGE,
        }),
    }
}

#[cfg(test)]
#[path = "reseal_tests.rs"]
mod tests;
