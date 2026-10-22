//! What the public routes read: the tenants this server is the issuer for, their key records, clients, codes, refresh
//! families, spent assertions, pairwise salts, pending authorizations, accounts, factors, sign-ins in progress,
//! passkeys, sessions and consents, the key-encryption key, the password pepper, the request counters and the clock.

use std::collections::HashMap;
use std::sync::Arc;

use tessari_oauth_infrastructure::custody::{Kek, Passwords};
use tessari_oauth_storage::audit::AuditService;
use tessari_oauth_storage::clients::ClientService;
use tessari_oauth_storage::codes::CodeService;
use tessari_oauth_storage::consents::ConsentService;
use tessari_oauth_storage::factors::FactorService;
use tessari_oauth_storage::interactions::InteractionService;
use tessari_oauth_storage::keys::KeyService;
use tessari_oauth_storage::passkeys::PasskeyService;
use tessari_oauth_storage::refresh::RefreshService;
use tessari_oauth_storage::replay::ReplayService;
use tessari_oauth_storage::sessions::SessionService;
use tessari_oauth_storage::signins::SigninService;
use tessari_oauth_storage::subjects::SubjectService;
use tessari_oauth_storage::throttle::{Limit, ThrottleService};
use tessari_oauth_storage::users::UserService;
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
    /// Second factors.
    pub factors: Arc<FactorService>,
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
    /// Each served tenant's issuer identifier, fixed at start-up from the configuration.
    pub issuers: Arc<HashMap<TenantId, String>>,
    /// The clock the key rule is judged at.
    pub clock: Clock,
}

impl PublicState {
    /// The served tenant the path segment `raw` names, with its issuer.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] for a segment that is not a tenant id or names a tenant this server does not serve — one
    /// answer for both, so the path is not an oracle for which tenants exist.
    pub(crate) fn tenant(&self, raw: &str) -> Result<(TenantId, &str)> {
        let tenant = TenantId::parse(raw).map_err(|_| Error::NotFound)?;
        let issuer = self.issuers.get(&tenant).ok_or(Error::NotFound)?;
        Ok((tenant, issuer.as_str()))
    }
}
