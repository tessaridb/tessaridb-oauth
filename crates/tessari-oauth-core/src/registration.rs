//! A company's registration policy: whether people may open their own account by address, and from which domains.
//! Closed until the company opens it. An open company with no domains admits any address; with domains, an address
//! whose domain is one of them exactly, so a subdomain is a domain of its own.

/// At most this many domains.
const MOST_DOMAINS: usize = 20;
/// The longest domain name DNS carries.
const LONGEST_DOMAIN: usize = 253;
/// The longest label DNS carries.
const LONGEST_LABEL: usize = 63;

/// Why a registration policy was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationRefused {
    /// A name is not a domain of two labels or more of letters, digits and inner hyphens.
    NotADomain,
    /// A domain is named twice.
    Repeated,
    /// More than twenty domains.
    TooMany,
}

/// A company's registration policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegistrationPolicy {
    open: bool,
    domains: Vec<String>,
}

impl RegistrationPolicy {
    /// The policy `open` or closed, admitting `domains` (any address when none), each kept lower-case.
    ///
    /// # Errors
    ///
    /// A name that is not a domain, a domain named twice, or more than twenty.
    pub fn new(open: bool, domains: Vec<String>) -> Result<Self, RegistrationRefused> {
        if domains.len() > MOST_DOMAINS {
            return Err(RegistrationRefused::TooMany);
        }
        let mut kept: Vec<String> = Vec::with_capacity(domains.len());
        for name in domains {
            let name = name.to_ascii_lowercase();
            if !is_domain(&name) {
                return Err(RegistrationRefused::NotADomain);
            }
            if kept.contains(&name) {
                return Err(RegistrationRefused::Repeated);
            }
            kept.push(name);
        }
        Ok(Self {
            open,
            domains: kept,
        })
    }

    /// Whether people may open their own account.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.open
    }

    /// The domains an address must belong to, lower-case; none means any.
    #[must_use]
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Whether `address` may open its own account under this policy.
    #[must_use]
    pub fn admits(&self, address: &str) -> bool {
        let Some((_, domain)) = address.rsplit_once('@') else {
            return false;
        };
        self.open
            && (self.domains.is_empty()
                || self
                    .domains
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(domain)))
    }
}

/// Whether `name` (lower-case) is a domain: two labels or more, each of letters, digits and inner hyphens.
fn is_domain(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= LONGEST_DOMAIN
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= LONGEST_LABEL
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
