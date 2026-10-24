//! Provisioning a company: its database and tables, and the client its admin console signs operators in through.
//!
//! The console is a client of the company's own issuer, so an operator signs in there like any user, with the
//! company's policy and factors. Its registration is the narrowest one that works: a public client redirected only to
//! the console's own callback, asking for `openid` and nothing else, addressed to the company's administration, and
//! holding no grant type, so the token endpoint refuses its codes to any caller. The console redeems them inside this
//! server.

use std::collections::BTreeSet;

use tessari_oauth_constants::{ADMIN_CONSOLE_CLIENT, COMPANY_PAGE_MAX, OPENID_SCOPE};
use tessari_oauth_core::clients::AuthMethod;
use tessari_oauth_types::{
    ClientId, ErrorCategory, RedirectUri, Resource, ScopeSet, TenantId, Timestamp,
};

use crate::clients::{ClientService, NewClient};
use crate::companies::CompanyStatus;
use crate::tenants::TenantService;
use crate::{Error, Result, Storage};

/// The admin console's client registration for `company`, whose issuer is under `public` and whose console is served
/// at `console`.
fn admin_console(company: &TenantId, public: &str, console: &str) -> Result<NewClient> {
    let invalid = |reason| Error::Invalid {
        record: "client",
        reason,
    };
    let home = format!("{console}/admin/{}", company.as_str());
    // The resource names the company's administration at its issuer, always https whatever the console is served
    // over.
    let resource = format!("{public}/{}/admin", company.as_str());
    Ok(NewClient {
        client_id: ClientId::parse(ADMIN_CONSOLE_CLIENT)
            .map_err(|_| invalid("the console's client id"))?,
        redirect_uris: vec![
            RedirectUri::parse(format!("{home}/callback"))
                .map_err(|_| invalid("the console's callback"))?,
        ],
        scope_ceiling: ScopeSet::parse(OPENID_SCOPE).map_err(|_| invalid("the console's scope"))?,
        resources: BTreeSet::from([
            Resource::parse(resource).map_err(|_| invalid("the console's resource"))?
        ]),
        auth_method: AuthMethod::None,
        grant_types: Vec::new(),
        jwks: Vec::new(),
        dpop_bound_access_tokens: false,
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        sector: None,
    })
}

impl Storage {
    /// Make `company`'s database and tables exist and register its admin console, served at `console`, as a client
    /// of its issuer under `public` at `now`; running it again only moves the console to the addresses given.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] when `console` does not make a callback URL.
    pub async fn provision_company(
        &self,
        company: &TenantId,
        public: &str,
        console: &str,
        now: Timestamp,
    ) -> Result<()> {
        provision(
            &self.tenants,
            &self.clients,
            company,
            (public, console),
            now,
        )
        .await
    }

    /// Provision again every company the region's directory serves, `active` or `suspended`, so the tables and fields
    /// a release added reach the companies made before it; one still `provisioning` is left to the request making it.
    /// Answers how many were provisioned.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] when `console` does not make a callback URL.
    pub async fn reprovision_companies(
        &self,
        public: &str,
        console: &str,
        now: Timestamp,
    ) -> Result<u64> {
        let mut provisioned: u64 = 0;
        let mut after: Option<TenantId> = None;
        loop {
            let page = self
                .companies
                .page(after.as_ref(), COMPANY_PAGE_MAX)
                .await?;
            let Some(last) = page.last() else {
                return Ok(provisioned);
            };
            after = Some(last.id.clone());
            for company in page {
                if company.status == CompanyStatus::Provisioning {
                    continue;
                }
                self.provision_company(&company.id, public, console, now)
                    .await?;
                provisioned = provisioned.saturating_add(1);
            }
        }
    }
}

/// [`Storage::provision_company`]) over the two services it needs, for a caller that holds them rather than the
/// whole storage.
///
/// # Errors
///
/// Store failures, and [`Error::Invalid`] when `console` does not make a callback URL.
pub async fn provision(
    tenants: &TenantService,
    clients: &ClientService,
    company: &TenantId,
    (public, console): (&str, &str),
    now: Timestamp,
) -> Result<()> {
    tenants.provision(company).await?;
    let client = admin_console(company, public, console)?;
    match clients.register(company, &client, now).await {
        // Registered by an earlier provisioning, perhaps under other addresses: it follows the ones the server runs
        // with now, so its callback and the resource its consent names are ones this server serves.
        Err(failure) if failure.category() == ErrorCategory::Conflict => {
            clients.retarget(company, &client).await
        }
        registered => registered.map(|_| ()),
    }
}
