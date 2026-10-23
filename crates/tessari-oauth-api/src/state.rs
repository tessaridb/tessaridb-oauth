//! What the public routes read: the tenants this server is the issuer for, their key records, clients, codes, refresh
//! families, spent assertions, pairwise salts, pending authorizations, accounts, factors, sign-ins in progress,
//! passkeys, sessions, consents and two-factor policies, the key-encryption key, the password pepper, the request
//! counters and the clock.

use std::sync::Arc;

use tessari_oauth_infrastructure::custody::{Kek, Passwords};
use tessari_oauth_storage::audit::AuditService;
use tessari_oauth_storage::brands::BrandService;
use tessari_oauth_storage::clients::ClientService;
use tessari_oauth_storage::codes::CodeService;
use tessari_oauth_storage::companies::{Elsewhere, Served};
use tessari_oauth_storage::consents::ConsentService;
use tessari_oauth_storage::email_changes::EmailChangeService;
use tessari_oauth_storage::enrolments::EnrolmentService;
use tessari_oauth_storage::factors::FactorService;
use tessari_oauth_storage::groups::GroupService;
use tessari_oauth_storage::interactions::InteractionService;
use tessari_oauth_storage::keys::KeyService;
use tessari_oauth_storage::mail_templates::MailTemplateService;
use tessari_oauth_storage::outbox::OutboxService;
use tessari_oauth_storage::passkeys::PasskeyService;
use tessari_oauth_storage::policies::PolicyService;
use tessari_oauth_storage::refresh::RefreshService;
use tessari_oauth_storage::replay::ReplayService;
use tessari_oauth_storage::resets::ResetService;
use tessari_oauth_storage::sessions::SessionService;
use tessari_oauth_storage::signins::SigninService;
use tessari_oauth_storage::subjects::SubjectService;
use tessari_oauth_storage::throttle::{Limit, ThrottleService};
use tessari_oauth_storage::users::UserService;
use tessari_oauth_storage::verifications::VerificationService;
use tessari_oauth_types::{Algorithm, Clock, TenantId};

use crate::{Error, Result};

/// The state the public router serves from. Everything in it is shared read-only, so no lock is ever taken.
#[derive(Clone)]
pub struct PublicState {
    /// The tenants' signing-key records.
    pub keys: Arc<KeyService>,
    /// Client registrations.
    pub clients: Arc<ClientService>,
    /// Authorization codes.
    pub codes: Arc<CodeService>,
    /// Refresh-token families.
    pub refresh: Arc<RefreshService>,
    /// Spent client assertions.
    pub replay: Arc<ReplayService>,
    /// Pairwise subjects.
    pub subjects: Arc<SubjectService>,
    /// Each company's groups, released at UserInfo under the `groups` scope.
    pub groups: Arc<GroupService>,
    /// Each company's brand and logo on its public pages.
    pub brands: Arc<BrandService>,
    /// The key-encryption key signing keys and salts are sealed under.
    pub kek: Arc<Kek>,
    /// The request counters.
    pub throttle: Arc<ThrottleService>,
    /// The audit trail every token and revocation outcome is appended to.
    pub audit: Arc<AuditService>,
    /// Authorization requests kept while their user signs in.
    pub interactions: Arc<InteractionService>,
    /// Accounts and their credentials.
    pub users: Arc<UserService>,
    /// One-time codes that let a user an operator created set a first password.
    pub enrolments: Arc<EnrolmentService>,
    /// Second factors.
    pub factors: Arc<FactorService>,
    /// Each tenant's two-factor policy.
    pub policies: Arc<PolicyService>,
    /// Sign-ins in progress, one per browser.
    pub signins: Arc<SigninService>,
    /// Passkeys and the challenges issued for them.
    pub passkeys: Arc<PasskeyService>,
    /// Sessions at this issuer.
    pub sessions: Arc<SessionService>,
    /// What each user granted each client.
    pub consents: Arc<ConsentService>,
    /// Password hashing and checking under the pepper, and the keys sign-in failures are counted under.
    pub passwords: Arc<Passwords>,
    /// How many metadata, key-set and UserInfo reads one client address may make per window.
    pub read_limit: Limit,
    /// How many token requests one client address may make per window.
    pub token_limit: Limit,
    /// How many authorization requests one client address may make per window.
    pub authorize_limit: Limit,
    /// How many sign-in steps one client address may post per window.
    pub login_limit: Limit,
    /// The algorithm the tenants' keys sign with — the server's choice, and the only one a token is verified under.
    pub signing_algorithm: Algorithm,
    /// The companies this node serves and their issuers, refreshed from the directory.
    pub served: Arc<Served>,
    /// The companies other regions serve, read from their directories; a request for one is sent there.
    pub elsewhere: Arc<Elsewhere>,
    /// The clock the key rule is judged at.
    pub clock: Clock,
    /// The mail owed and not yet sent.
    pub outbox: Arc<OutboxService>,
    /// Password-reset tokens.
    pub resets: Arc<ResetService>,
    /// The address-verification tokens mail carries.
    pub verifications: Arc<VerificationService>,
    /// Requested changes of a sign-in address.
    pub email_changes: Arc<EmailChangeService>,
    /// The wording of the mail the server sends.
    pub mail_templates: Arc<MailTemplateService>,
    /// Whether a mail relay is configured, so the flows that send mail are offered.
    pub mail: bool,
}

impl PublicState {
    /// The served tenant the path segment `raw` names, with its issuer.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] for a segment that is not a tenant id or names a tenant this server does not serve — one
    /// answer for both, so the path is not an oracle for which tenants exist.
    pub(crate) fn tenant(&self, raw: &str) -> Result<(TenantId, Arc<str>)> {
        let tenant = TenantId::parse(raw).map_err(|_| Error::NotFound)?;
        let issuer = self.served.issuer(&tenant).ok_or(Error::NotFound)?;
        Ok((tenant, issuer))
    }
}
