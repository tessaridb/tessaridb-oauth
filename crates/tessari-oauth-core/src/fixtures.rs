//! Fixtures shared by this crate's tests: two tenants, a public client in each, an in-memory directory.

use tessari_oauth_types::{ClientId, RedirectUri, ScopeSet, TenantId};

use crate::clients::{AuthMethod, ClientDirectory, ClientRegistration};

/// The tenant the requests are for.
pub(crate) fn acme() -> TenantId {
    TenantId::parse("acme").expect("fixture tenant")
}

/// A second tenant, whose clients must never be found from the first.
pub(crate) fn globex() -> TenantId {
    TenantId::parse("globex").expect("fixture tenant")
}

/// The issuer of `acme`.
pub(crate) const ACME_ISSUER: &str = "https://id.example.com/acme";

/// The redirect URI the fixture client registered.
pub(crate) const REDIRECT: &str = "https://app.example.com/callback";

/// RFC 7636 Appendix B pair.
pub(crate) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub(crate) const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// A public client of `tenant` named `id`, registered with `redirects`.
pub(crate) fn client(tenant: TenantId, id: &str, redirects: &[&str]) -> ClientRegistration {
    ClientRegistration {
        tenant,
        client_id: ClientId::parse(id).expect("fixture client id"),
        redirect_uris: redirects
            .iter()
            .map(|raw| RedirectUri::parse(*raw).expect("fixture redirect"))
            .collect(),
        scope_ceiling: ScopeSet::parse("openid profile notes:read").expect("fixture ceiling"),
        auth_method: AuthMethod::None,
    }
}

/// An in-memory directory over `clients`.
pub(crate) struct Directory(pub(crate) Vec<ClientRegistration>);

impl ClientDirectory for Directory {
    fn find(&self, tenant: &TenantId, client_id: &ClientId) -> Option<ClientRegistration> {
        self.0
            .iter()
            .find(|registration| {
                registration.tenant == *tenant && registration.client_id == *client_id
            })
            .cloned()
    }
}

/// `acme` holds `app` (one redirect) and `multi` (two); `globex` holds `other`.
pub(crate) fn directory() -> Directory {
    Directory(vec![
        client(acme(), "app", &[REDIRECT]),
        client(
            acme(),
            "multi",
            &[REDIRECT, "https://app.example.com/other"],
        ),
        client(acme(), "native", &["http://127.0.0.1/callback"]),
        client(globex(), "other", &["https://other.example.com/cb"]),
    ])
}

/// A directory that ignores the tenant — the storage defect the core must survive: it returns `other` of `globex`
/// to a lookup made for `acme`.
pub(crate) struct CarelessDirectory;

impl ClientDirectory for CarelessDirectory {
    fn find(&self, _tenant: &TenantId, client_id: &ClientId) -> Option<ClientRegistration> {
        directory()
            .0
            .into_iter()
            .find(|registration| registration.client_id == *client_id)
    }
}
