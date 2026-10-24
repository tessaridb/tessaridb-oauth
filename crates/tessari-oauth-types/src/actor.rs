//! Who acts on a company's admin API: an operator signed in to the console, or a service the company registered.

use crate::{ServiceId, UserId};

/// The caller an admin change or read is made by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Actor {
    /// A company user signed in to the console with an operator role.
    Operator(UserId),
    /// A registered service, by its signed assertion.
    Service(ServiceId),
}

impl Actor {
    /// The actor as records name it: an operator by their user id, as always, and a service as `service:<id>`. A user
    /// id holds no `:`, so the two never name one actor.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Operator(user) => user.as_str().to_owned(),
            Self::Service(service) => format!("service:{}", service.as_str()),
        }
    }
}

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
