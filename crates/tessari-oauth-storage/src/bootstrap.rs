//! The emergency path that makes a platform operator when no operator can: the first one at installation, or one
//! whose access was lost. It needs nothing but the store, so it works while the server does not.
//!
//! It makes the `system` company when there is none and serves it, finds or registers the account signing in with the
//! address given, and gives it `companies` and `users` in the name of `break-glass` rather than of any operator. An
//! account with no password yet is issued the enrolment code the caller minted, replacing any earlier one; an account
//! that has one keeps it, so the path never takes over a credential. Every run is appended to the `system` company's
//! audit trail as `break_glass`, after the grants it made.

use tessari_oauth_constants::SYSTEM_COMPANY;
use tessari_oauth_types::{EmailAddress, EnrolmentCode, TenantId, Timestamp, UserId};

use crate::audit::{AuditEvent, AuditKind};
use crate::companies::CompanyStatus;
use crate::operators::{Granted, OperatorGrant, OperatorRole};
use crate::users::Registered;
use crate::{Error, Result, Storage};

/// The name the emergency path acts under on the audit trail and in the grants it makes.
const BREAK_GLASS: &str = "break-glass";

/// Why the emergency path gave its grants.
const BOOTSTRAP_REASON: &str = "bootstrap-operator";

/// The roles the emergency path gives: enough to make companies and their first users, nothing more.
const BOOTSTRAP_ROLES: [OperatorRole; 2] = [OperatorRole::Companies, OperatorRole::Users];

/// What the emergency path did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrapped {
    /// The operator's account in the `system` company.
    pub user: UserId,
    /// Whether the code was issued: the account had no password yet.
    pub code_issued: bool,
}

fn system() -> Result<TenantId> {
    TenantId::parse(SYSTEM_COMPANY).map_err(|_| Error::Invalid {
        record: "company",
        reason: "the system company's id outside the tenant grammar",
    })
}

impl Storage {
    /// Make the platform operator signing in with `email` at `now`, issuing `code` when the account has no
    /// password; the system company is provisioned with its issuer under `public` and its admin console served at
    /// `console`.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] when the account disappears between registering and reading it.
    pub async fn bootstrap_operator(
        &self,
        email: &EmailAddress,
        code: &EnrolmentCode,
        public: &str,
        console: &str,
        now: Timestamp,
    ) -> Result<Bootstrapped> {
        let system = system()?;
        self.companies.prepare().await?;
        self.companies
            .create(&system, "Platform operators", BREAK_GLASS, now)
            .await?;
        self.provision_company(&system, public, console, now)
            .await?;
        // Already active is fine; a suspended system company stays suspended, as any other would.
        self.companies
            .transition(&system, CompanyStatus::Provisioning, CompanyStatus::Active)
            .await?;
        let user = match self.users.register(&system, email, now).await? {
            Registered::Created(user) => user,
            Registered::AddressTaken => {
                self.users
                    .find_by_email(&system, email)
                    .await?
                    .ok_or(Error::Invalid {
                        record: "user",
                        reason: "the address names no account",
                    })?
                    .user
            }
        };
        for role in BOOTSTRAP_ROLES {
            let grant = OperatorGrant {
                user: user.clone(),
                role,
                granted_by: BREAK_GLASS.to_owned(),
                granted_at: now,
                reason: BOOTSTRAP_REASON.to_owned(),
                expires_at: None,
            };
            if self.operators.grant(&system, &grant).await? != Granted::Granted {
                return Err(Error::Invalid {
                    record: "operator grant",
                    reason: "the emergency path's grant was refused",
                });
            }
        }
        let code_issued = self.users.password(&system, &user).await?.is_none();
        if code_issued {
            self.enrolments
                .issue(&system, code, &user, BREAK_GLASS, now)
                .await?;
        }
        let event = AuditEvent {
            user: Some(user.clone()),
            actor: Some(BREAK_GLASS.to_owned()),
            reason: Some(BOOTSTRAP_REASON.to_owned()),
            ..AuditEvent::of(AuditKind::BreakGlass)
        };
        self.audit.record(&system, &event, now).await?;
        Ok(Bootstrapped { user, code_issued })
    }
}
