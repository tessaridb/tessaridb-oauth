//! The storage aggregate: every domain's service, assembled in one place.

use std::sync::Arc;

use tessari_oauth_infrastructure::tessaridb::Database;

use crate::Tenancy;
use crate::audit::{AuditService, TessaridbAuditRepository};
use crate::clients::{ClientService, TessaridbClientRepository};
use crate::codes::{CodeService, TessaridbCodeRepository};
use crate::companies::{CompanyService, TessaridbCompanyRepository};
use crate::consents::{ConsentService, TessaridbConsentRepository};
use crate::factors::{FactorService, TessaridbFactorRepository};
use crate::interactions::{InteractionService, TessaridbInteractionRepository};
use crate::keys::{KeyService, TessaridbKeyRepository};
use crate::logouts::{LogoutService, TessaridbLogoutRepository};
use crate::passkeys::{PasskeyService, TessaridbPasskeyRepository};
use crate::policies::{PolicyService, TessaridbPolicyRepository};
use crate::refresh::{RefreshService, TessaridbRefreshRepository};
use crate::replay::{ReplayService, TessaridbReplayRepository};
use crate::sessions::{SessionService, TessaridbSessionRepository};
use crate::signins::{SigninService, TessaridbSigninRepository};
use crate::subjects::{SubjectService, TessaridbSecretRepository};
use crate::tenants::{TenantService, TessaridbTenantRepository};
use crate::throttle::{TessaridbThrottleRepository, ThrottleService};
use crate::users::{TessaridbUserRepository, UserService};

/// The services the server reaches its records through.
#[derive(Clone)]
pub struct Storage {
    /// The region's directory of companies.
    pub companies: Arc<CompanyService>,
    /// Tenant provisioning.
    pub tenants: Arc<TenantService>,
    /// Client registrations.
    pub clients: Arc<ClientService>,
    /// Authorization codes.
    pub codes: Arc<CodeService>,
    /// Pending authorizations.
    pub interactions: Arc<InteractionService>,
    /// Users' grants to clients.
    pub consents: Arc<ConsentService>,
    /// Refresh-token families.
    pub refresh: Arc<RefreshService>,
    /// Spent client assertions and DPoP proofs.
    pub replay: Arc<ReplayService>,
    /// Signing keys.
    pub keys: Arc<KeyService>,
    /// Pairwise subjects and the salt they are made under.
    pub subjects: Arc<SubjectService>,
    /// Request counters.
    pub throttle: Arc<ThrottleService>,
    /// Accounts and their credentials.
    pub users: Arc<UserService>,
    /// Second factors.
    pub factors: Arc<FactorService>,
    /// Each company's policies.
    pub policies: Arc<PolicyService>,
    /// Passkeys and their challenges.
    pub passkeys: Arc<PasskeyService>,
    /// Sign-ins in progress.
    pub signins: Arc<SigninService>,
    /// Sessions at this issuer.
    pub sessions: Arc<SessionService>,
    /// The logouts owed to clients of ended sessions.
    pub logouts: Arc<LogoutService>,
    /// The audit trail.
    pub audit: Arc<AuditService>,
}

impl Storage {
    /// Assemble the services over `database`, for the region `tenancy` names.
    #[must_use]
    pub fn new(database: &Database, tenancy: &Tenancy) -> Self {
        let company_repository = Arc::new(TessaridbCompanyRepository::new(database.clone()));
        let tenant_repository = Arc::new(TessaridbTenantRepository::new(database.clone()));
        let client_repository = Arc::new(TessaridbClientRepository::new(database.clone()));
        let code_repository = Arc::new(TessaridbCodeRepository::new(database.clone()));
        let interaction_repository =
            Arc::new(TessaridbInteractionRepository::new(database.clone()));
        let consent_repository = Arc::new(TessaridbConsentRepository::new(database.clone()));
        let refresh_repository = Arc::new(TessaridbRefreshRepository::new(database.clone()));
        let replay_repository = Arc::new(TessaridbReplayRepository::new(database.clone()));
        let key_repository = Arc::new(TessaridbKeyRepository::new(database.clone()));
        let secret_repository = Arc::new(TessaridbSecretRepository::new(database.clone()));
        let throttle_repository = Arc::new(TessaridbThrottleRepository::new(database.clone()));
        let audit_repository = Arc::new(TessaridbAuditRepository::new(database.clone()));
        let user_repository = Arc::new(TessaridbUserRepository::new(database.clone()));
        let factor_repository = Arc::new(TessaridbFactorRepository::new(database.clone()));
        let policy_repository = Arc::new(TessaridbPolicyRepository::new(database.clone()));
        let passkey_repository = Arc::new(TessaridbPasskeyRepository::new(database.clone()));

        let signin_repository = Arc::new(TessaridbSigninRepository::new(database.clone()));

        let session_repository = Arc::new(TessaridbSessionRepository::new(database.clone()));
        let logout_repository = Arc::new(TessaridbLogoutRepository::new(database.clone()));
        let audit = Arc::new(AuditService::new(audit_repository, tenancy.clone()));
        Self {
            companies: Arc::new(CompanyService::new(company_repository, tenancy.clone())),
            tenants: Arc::new(TenantService::new(tenant_repository, tenancy.clone())),
            clients: Arc::new(ClientService::new(client_repository, tenancy.clone())),
            codes: Arc::new(CodeService::new(code_repository, tenancy.clone())),
            interactions: Arc::new(InteractionService::new(
                interaction_repository,
                tenancy.clone(),
            )),
            consents: Arc::new(ConsentService::new(consent_repository, tenancy.clone())),
            refresh: Arc::new(RefreshService::new(
                refresh_repository,
                tenancy.clone(),
                Arc::clone(&audit),
            )),
            replay: Arc::new(ReplayService::new(replay_repository, tenancy.clone())),
            keys: Arc::new(KeyService::new(key_repository, tenancy.clone())),
            subjects: Arc::new(SubjectService::new(secret_repository, tenancy.clone())),
            throttle: Arc::new(ThrottleService::new(throttle_repository, tenancy.clone())),
            users: Arc::new(UserService::new(user_repository, tenancy.clone())),
            factors: Arc::new(FactorService::new(factor_repository, tenancy.clone())),
            policies: Arc::new(PolicyService::new(policy_repository, tenancy.clone())),
            passkeys: Arc::new(PasskeyService::new(passkey_repository, tenancy.clone())),
            signins: Arc::new(SigninService::new(signin_repository, tenancy.clone())),
            sessions: Arc::new(SessionService::new(session_repository, tenancy.clone())),
            logouts: Arc::new(LogoutService::new(logout_repository, tenancy.clone())),
            audit,
        }
    }
}
