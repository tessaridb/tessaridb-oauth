use tessari_oauth_types::{ErrorCode, Resource, ScopeSet};

use super::{ClientGrant, grant};
use crate::Reason;
use crate::clients::ClientRegistration;
use crate::fixtures::{REDIRECT, acme, client};
use crate::token::{Refusal, read};

const API: &str = "https://api.example.com/";
const FILES: &str = "https://files.example.com/";

fn resource(raw: &str) -> Resource {
    Resource::parse(raw).expect("a resource")
}

/// A client whose ceiling is `notes:read notes:write` at `resources`.
fn service(resources: &[&str]) -> ClientRegistration {
    let mut registration = client(acme(), "svc", &[REDIRECT]);
    registration.scope_ceiling = ScopeSet::parse("notes:read notes:write").expect("a ceiling");
    registration.resources = resources.iter().map(|raw| resource(raw)).collect();
    registration
}

fn request(extra: &[(&'static str, &str)]) -> crate::Params {
    let mut pairs = vec![("grant_type", "client_credentials".to_owned())];
    pairs.extend(
        extra
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned())),
    );
    read(pairs).expect("no repeats")
}

fn refused(error: ErrorCode, reason: Reason) -> Result<ClientGrant, Refusal> {
    Err(Refusal { error, reason })
}

#[test]
fn the_named_scopes_within_the_ceiling_are_granted_at_the_one_resource() {
    assert_eq!(
        grant(&request(&[("scope", "notes:read")]), &service(&[API])),
        Ok(ClientGrant {
            scopes: ScopeSet::parse("notes:read").expect("scopes"),
            audience: resource(API),
        })
    );
    assert_eq!(
        grant(
            &request(&[("scope", "notes:read notes:write"), ("resource", FILES)]),
            &service(&[API, FILES])
        )
        .map(|granted| granted.audience),
        Ok(resource(FILES))
    );
}

#[test]
fn a_scope_must_be_named_well_formed_and_within_the_ceiling() {
    let svc = service(&[API]);
    assert_eq!(
        grant(&request(&[]), &svc),
        refused(ErrorCode::InvalidScope, Reason::MissingParameter)
    );
    assert_eq!(
        grant(&request(&[("scope", "notes:read  bad\u{7f}")]), &svc),
        refused(ErrorCode::InvalidScope, Reason::MalformedParameter)
    );
    assert_eq!(
        grant(&request(&[("scope", "notes:read notes:admin")]), &svc),
        refused(ErrorCode::InvalidScope, Reason::ScopeBeyondCeiling)
    );
}

#[test]
fn openid_is_refused_because_no_user_stands_behind_the_token() {
    let mut svc = service(&[API]);
    svc.scope_ceiling = ScopeSet::parse("openid notes:read").expect("a ceiling");
    for asked in ["openid", "notes:read openid"] {
        assert_eq!(
            grant(&request(&[("scope", asked)]), &svc),
            refused(ErrorCode::InvalidScope, Reason::OpenIdWithoutUser),
            "{asked}"
        );
    }
    assert!(grant(&request(&[("scope", "notes:read")]), &svc).is_ok());
}

#[test]
fn the_audience_is_one_of_the_clients_resources() {
    assert_eq!(
        grant(
            &request(&[("scope", "notes:read"), ("resource", FILES)]),
            &service(&[API])
        ),
        refused(ErrorCode::InvalidTarget, Reason::TargetNotGranted)
    );
    assert_eq!(
        grant(
            &request(&[("scope", "notes:read")]),
            &service(&[API, FILES])
        ),
        refused(ErrorCode::InvalidTarget, Reason::TargetUnnamed)
    );
    assert_eq!(
        grant(&request(&[("scope", "notes:read")]), &service(&[])),
        refused(ErrorCode::InvalidTarget, Reason::TargetUnnamed)
    );
}
