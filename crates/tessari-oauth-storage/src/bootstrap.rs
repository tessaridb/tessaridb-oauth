//! The emergency path that makes an operator when no operator can: the first platform operator at installation, the
//! first operator of a company made since, or one whose access was lost. It needs nothing but the store, so it works
//! while the server does not.
//!
//! For `system` it makes the company when there is none and serves it, and gives `companies` and `users`; for any
//! other company it acts only on one that exists and is served, and gives that company's five console roles, never
//! `companies`. Either way it finds or registers the account signing in with the address given and grants in the
//! name of `break-glass` rather than of any operator. An account with no password yet is issued the enrolment code
//! the caller minted, replacing any earlier one; an account that has one keeps it, so the path never takes over a
//! credential. Every run is appended to that company's audit trail as `break_glass`, after the grants it made.

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

/// The roles the emergency path gives in `system`: enough to make companies and their first users, nothing more.
const SYSTEM_ROLES: [OperatorRole; 2] = [OperatorRole::Companies, OperatorRole::Users];

/// The roles it gives in any other company: every console role there, `companies` being held only in `system`.
const COMPANY_ROLES: [OperatorRole; 5] = [
    OperatorRole::Users,
    OperatorRole::Clients,
    OperatorRole::Policy,
    OperatorRole::Keys,
    OperatorRole::Audit,
];

/// What the emergency path did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrapped {
    /// The operator's account in the company it was made for.
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
    /// Make the operator of `company` signing in with `email` at `now`, issuing `code` when the account has no
    /// password. For `system` the company is made when missing and provisioned with its issuer under `public` and its
    /// admin console served at `console`; any other company must already be served.
    ///
    /// # Errors
    ///
    /// Store failures; [`Error::Invalid`] for `company` when a company other than `system` is not served (unknown,
    /// provisioning or suspended), nothing being written, and when the account disappears between registering and
    /// reading it.
    pub async fn bootstrap_operator(
        &self,
        company: &TenantId,
        email: &EmailAddress,
        code: &EnrolmentCode,
        public: &str,
        console: &str,
        now: Timestamp,
    ) -> Result<Bootstrapped> {
        self.companies.prepare().await?;
        let roles: &[OperatorRole] = if *company == system()? {
            self.companies
                .create(company, "Platform operators", BREAK_GLASS, now)
                .await?;
            self.provision_company(company, public, console, now)
                .await?;
            // Already active is fine; a suspended system company stays suspended, as any other would.
            self.companies
                .transition(company, CompanyStatus::Provisioning, CompanyStatus::Active)
                .await?;
            &SYSTEM_ROLES
        } else {
            let served = self
                .companies
                .find(company)
                .await?
                .is_some_and(|found| found.status == CompanyStatus::Active);
            if !served {
                return Err(Error::Invalid {
                    record: "company",
                    reason: "no company with this id is served; create or resume it first",
                });
            }
            &COMPANY_ROLES
        };
        let user = match self.users.register(company, email, now).await? {
            Registered::Created(user) => user,
            Registered::AddressTaken => {
                self.users
                    .find_by_email(company, email)
                    .await?
                    .ok_or(Error::Invalid {
                        record: "user",
                        reason: "the address names no account",
                    })?
                    .user
            }
        };
        for &role in roles {
            let grant = OperatorGrant {
                user: user.clone(),
                role,
                granted_by: BREAK_GLASS.to_owned(),
                granted_at: now,
                reason: BOOTSTRAP_REASON.to_owned(),
                expires_at: None,
            };
            if self.operators.grant(company, &grant).await? != Granted::Granted {
                return Err(Error::Invalid {
                    record: "operator grant",
                    reason: "the emergency path's grant was refused",
                });
            }
        }
        let code_issued = self.users.password(company, &user).await?.is_none();
        if code_issued {
            self.enrolments
                .issue(company, code, &user, BREAK_GLASS, now)
                .await?;
        }
        let event = AuditEvent {
            user: Some(user.clone()),
            actor: Some(BREAK_GLASS.to_owned()),
            reason: Some(BOOTSTRAP_REASON.to_owned()),
            ..AuditEvent::of(AuditKind::BreakGlass)
        };
        self.audit.record(company, &event, now).await?;
        Ok(Bootstrapped { user, code_issued })
    }
}
