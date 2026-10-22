//! What `bootstrap-operator` is asked to do, read from the words after the subcommand: the company, `system` unless
//! `--company` names another, and the address of the operator's account.

use tessari_oauth_constants::SYSTEM_COMPANY;
use tessari_oauth_types::{EmailAddress, TenantId};

use crate::{Error, Result};

/// The words `bootstrap-operator` accepts after its name.
const USAGE: &str = "[--company <id>] --email <address>";

/// The company and address `arguments` name, `--company` given before or after `--email` or left out for `system`.
///
/// # Errors
///
/// [`Error::Invalid`] naming the usage for any other arrangement of words, or naming the flag whose value does not
/// read as a company id or an email address.
pub fn operator_target(arguments: &[String]) -> Result<(TenantId, EmailAddress)> {
    let usage = || Error::Invalid {
        key: "arguments",
        value: arguments.join(" "),
        reason: USAGE,
    };
    let (company, address) = match arguments {
        [flag, address] if flag == "--email" => (SYSTEM_COMPANY, address),
        [first, one, second, other] => match (first.as_str(), second.as_str()) {
            ("--company", "--email") => (one.as_str(), other),
            ("--email", "--company") => (other.as_str(), one),
            _ => return Err(usage()),
        },
        _ => return Err(usage()),
    };
    let company = TenantId::parse(company).map_err(|_| Error::Invalid {
        key: "--company",
        value: company.to_owned(),
        reason: "a company id: 1 to 63 lowercase letters, digits and inner hyphens",
    })?;
    let email = EmailAddress::parse(address.as_str()).map_err(|_| Error::Invalid {
        key: "--email",
        value: address.clone(),
        reason: "an email address",
    })?;
    Ok((company, email))
}

#[cfg(test)]
#[path = "operator_tests.rs"]
mod tests;
