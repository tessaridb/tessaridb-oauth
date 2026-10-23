//! The storage aggregate: every domain's service, assembled in one place.

use std::sync::Arc;

use tessari_oauth_infrastructure::tessaridb::Database;

use crate::Tenancy;
use crate::admin::{AdminService, TessaridbAdminRepository};
use crate::audit::{AuditService, TessaridbAuditRepository};
use crate::brands::{BrandService, TessaridbBrandRepository};
use crate::client_removal::ClientRemovalService;
use crate::clients::{ClientService, TessaridbClientRepository};
use crate::codes::{CodeService, TessaridbCodeRepository};
use crate::companies::{CompanyService, TessaridbCompanyRepository};
use crate::consents::{ConsentService, TessaridbConsentRepository};
use crate::enrolments::{EnrolmentService, TessaridbEnrolmentRepository};
use crate::factors::{FactorService, TessaridbFactorRepository};
use crate::groups::{GroupService, TessaridbGroupRepository};
use crate::interactions::{InteractionService, TessaridbInteractionRepository};
use crate::keys::{KeyService, TessaridbKeyRepository};
use crate::logouts::{LogoutService, TessaridbLogoutRepository};
use crate::operators::{OperatorService, TessaridbOperatorRepository};
use crate::outbox::{OutboxService, TessaridbOutboxRepository};
use crate::passkeys::{PasskeyService, TessaridbPasskeyRepository};
use crate::policies::{PolicyService, TessaridbPolicyRepository};
use crate::refresh::{RefreshService, TessaridbRefreshRepository};
use crate::replay::{ReplayService, TessaridbReplayRepository};
use crate::resets::{ResetService, TessaridbResetRepository};
use crate::sessions::{SessionService, TessaridbSessionRepository};
use crate::signins::{SigninService, TessaridbSigninRepository};
use crate::subjects::{SubjectService, TessaridbSecretRepository};
use crate::tenants::{TenantService, TessaridbTenantRepository};
use crate::throttle::{TessaridbThrottleRepository, ThrottleService};
use crate::users::{TessaridbUserRepository, UserService};
use crate::verifications::{TessaridbVerificationRepository, VerificationService};

/// The services the server reaches its records through.
#[derive(Clone)]
pub struct Storage {
    /// The region's directory of companies.
    pub companies: Arc<CompanyService>,
    /// Tenant provisioning.
    pub tenants: Arc<TenantService>,
    /// Client registrations.
    pub clients: Arc<ClientService>,
    /// Removing a client with everything it held.
    pub client_removals: Arc<ClientRemovalService>,
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
    /// One-time codes that let a user an operator created set a first credential.
    pub enrolments: Arc<EnrolmentService>,
    /// Second factors.
    pub factors: Arc<FactorService>,
    /// Each company's policies.
    pub policies: Arc<PolicyService>,
    /// Each company's groups and who is in them.
    pub groups: Arc<GroupService>,
    /// Each company's brand and logo on its public pages.
    pub brands: Arc<BrandService>,
    /// Passkeys and their challenges.
    pub passkeys: Arc<PasskeyService>,
    /// Sign-ins in progress.
    pub signins: Arc<SigninService>,
    /// Sessions at this issuer.
    pub sessions: Arc<SessionService>,
    /// The logouts owed to clients of ended sessions.
    pub logouts: Arc<LogoutService>,
    /// The mail owed and not yet sent.
    pub outbox: Arc<OutboxService>,
    /// The password-reset tokens mail carries.
    pub resets: Arc<ResetService>,
    /// The address-verification tokens mail carries.
    pub verifications: Arc<VerificationService>,
    /// Which users of each company may administer it, and for which tasks.
    pub operators: Arc<OperatorService>,
    /// Admin console sign-ins and sessions.
    pub admin: Arc<AdminService>,
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
        let enrolment_repository = Arc::new(TessaridbEnrolmentRepository::new(database.clone()));
        let factor_repository = Arc::new(TessaridbFactorRepository::new(database.clone()));
        let policy_repository = Arc::new(TessaridbPolicyRepository::new(database.clone()));
        let passkey_repository = Arc::new(TessaridbPasskeyRepository::new(database.clone()));
        let group_repository = Arc::new(TessaridbGroupRepository::new(database.clone()));
        let brand_repository = Arc::new(TessaridbBrandRepository::new(database.clone()));

        let signin_repository = Arc::new(TessaridbSigninRepository::new(database.clone()));

        let session_repository = Arc::new(TessaridbSessionRepository::new(database.clone()));
        let logout_repository = Arc::new(TessaridbLogoutRepository::new(database.clone()));
        let outbox_repository = Arc::new(TessaridbOutboxRepository::new(database.clone()));
        let reset_repository = Arc::new(TessaridbResetRepository::new(database.clone()));
        let verification_repository =
            Arc::new(TessaridbVerificationRepository::new(database.clone()));
        let operator_repository = Arc::new(TessaridbOperatorRepository::new(database.clone()));
        let admin_repository = Arc::new(TessaridbAdminRepository::new(database.clone()));
        let audit = Arc::new(AuditService::new(audit_repository, tenancy.clone()));
        let clients = Arc::new(ClientService::new(client_repository, tenancy.clone()));
        let consents = Arc::new(ConsentService::new(consent_repository, tenancy.clone()));
        let refresh = Arc::new(RefreshService::new(
            refresh_repository,
            tenancy.clone(),
            Arc::clone(&audit),
        ));
        Self {
            companies: Arc::new(CompanyService::new(company_repository, tenancy.clone())),
            tenants: Arc::new(TenantService::new(tenant_repository, tenancy.clone())),
            client_removals: Arc::new(ClientRemovalService::new(
                Arc::clone(&clients),
                Arc::clone(&consents),
                Arc::clone(&refresh),
            )),
            clients,
            codes: Arc::new(CodeService::new(code_repository, tenancy.clone())),
            interactions: Arc::new(InteractionService::new(
                interaction_repository,
                tenancy.clone(),
            )),
            consents,
            refresh,
            replay: Arc::new(ReplayService::new(replay_repository, tenancy.clone())),
            keys: Arc::new(KeyService::new(key_repository, tenancy.clone())),
            subjects: Arc::new(SubjectService::new(secret_repository, tenancy.clone())),
            throttle: Arc::new(ThrottleService::new(throttle_repository, tenancy.clone())),
            users: Arc::new(UserService::new(user_repository, tenancy.clone())),
            enrolments: Arc::new(EnrolmentService::new(enrolment_repository, tenancy.clone())),
            factors: Arc::new(FactorService::new(factor_repository, tenancy.clone())),
            policies: Arc::new(PolicyService::new(policy_repository, tenancy.clone())),
            groups: Arc::new(GroupService::new(group_repository, tenancy.clone())),
            brands: Arc::new(BrandService::new(brand_repository, tenancy.clone())),
            passkeys: Arc::new(PasskeyService::new(passkey_repository, tenancy.clone())),
            signins: Arc::new(SigninService::new(signin_repository, tenancy.clone())),
            sessions: Arc::new(SessionService::new(session_repository, tenancy.clone())),
            logouts: Arc::new(LogoutService::new(logout_repository, tenancy.clone())),
            outbox: Arc::new(OutboxService::new(outbox_repository, tenancy.clone())),
            resets: Arc::new(ResetService::new(reset_repository, tenancy.clone())),
            verifications: Arc::new(VerificationService::new(
                verification_repository,
                tenancy.clone(),
            )),
            operators: Arc::new(OperatorService::new(
                operator_repository,
                tenancy.clone(),
                Arc::clone(&audit),
            )),
            admin: Arc::new(AdminService::new(admin_repository, tenancy.clone())),
            audit,
        }
    }
}
