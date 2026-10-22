//! Provisioning a company: its database and tables, and the client its admin console signs operators in through.
//!
//! The console is a client of the company's own issuer, so an operator signs in there like any user, with the
//! company's policy and factors. Its registration is the narrowest one that works: a public client redirected only to
//! the console's own callback, asking for `openid` and nothing else, addressed to the company's administration, and
//! holding no grant type, so the token endpoint refuses its codes to any caller. The console redeems them inside this
//! server.

use std::collections::BTreeSet;

use tessari_oauth_constants::{ADMIN_CONSOLE_CLIENT, OPENID_SCOPE};
use tessari_oauth_core::clients::AuthMethod;
use tessari_oauth_types::{
    ClientId, ErrorCategory, RedirectUri, Resource, ScopeSet, TenantId, Timestamp,
};

use crate::clients::NewClient;
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
    })
}

impl Storage {
    /// Make `company`'s database and tables exist and register its admin console, served at `console`, as a client
    /// of its issuer under `public` at `now`; running it again changes nothing.
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
        self.tenants.provision(company).await?;
        match self
            .clients
            .register(company, &admin_console(company, public, console)?, now)
            .await
        {
            // Registered by an earlier provisioning.
            Err(failure) if failure.category() == ErrorCategory::Conflict => Ok(()),
            registered => registered.map(|_| ()),
        }
    }
}
