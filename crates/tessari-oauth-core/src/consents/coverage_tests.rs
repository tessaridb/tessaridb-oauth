use std::collections::BTreeSet;

use tessari_oauth_types::{Resource, ScopeSet};

use super::{ConsentRequest, Coverage, GrantedConsent, coverage};

const POLICY: u32 = 3;
const OLDER_POLICY: u32 = 2;

fn scopes(raw: &str) -> ScopeSet {
    ScopeSet::parse(raw).expect("fixture scopes")
}

fn resources(raw: &[&str]) -> BTreeSet<Resource> {
    raw.iter()
        .map(|uri| Resource::parse(*uri).expect("fixture resource"))
        .collect()
}

fn granted() -> GrantedConsent {
    GrantedConsent {
        scopes: scopes("openid profile"),
        resources: resources(&["https://api.example.com/"]),
        policy_version: POLICY,
        revoked: false,
    }
}

fn request(scope: &str, at: &[&str]) -> ConsentRequest {
    ConsentRequest {
        scopes: scopes(scope),
        resources: resources(at),
    }
}

fn whole(request: &ConsentRequest) -> Coverage {
    Coverage::Prompt {
        scopes: Some(request.scopes.clone()),
        resources: request.resources.clone(),
    }
}

#[test]
fn a_request_inside_the_grant_is_covered() {
    let asked = request("openid", &["https://api.example.com/"]);
    assert_eq!(
        coverage(Some(&granted()), &asked, POLICY),
        Coverage::Covered
    );
}

#[test]
fn a_scope_outside_the_grant_prompts_for_that_scope_alone() {
    let asked = request("openid payments", &["https://api.example.com/"]);
    let expected = Coverage::Prompt {
        scopes: Some(scopes("payments")),
        resources: BTreeSet::new(),
    };
    assert_eq!(coverage(Some(&granted()), &asked, POLICY), expected);
}

#[test]
fn a_resource_outside_the_grant_prompts_for_that_resource_alone() {
    let asked = request(
        "openid",
        &["https://api.example.com/", "https://billing.example.com/"],
    );
    let expected = Coverage::Prompt {
        scopes: None,
        resources: resources(&["https://billing.example.com/"]),
    };
    assert_eq!(coverage(Some(&granted()), &asked, POLICY), expected);
}

#[test]
fn no_grant_a_revoked_grant_and_a_grant_under_an_older_policy_prompt_for_everything() {
    let asked = request("openid", &["https://api.example.com/"]);
    let revoked = GrantedConsent {
        revoked: true,
        ..granted()
    };
    let older = GrantedConsent {
        policy_version: OLDER_POLICY,
        ..granted()
    };
    assert_eq!(coverage(None, &asked, POLICY), whole(&asked), "no grant");
    assert_eq!(
        coverage(Some(&revoked), &asked, POLICY),
        whole(&asked),
        "revoked"
    );
    assert_eq!(
        coverage(Some(&older), &asked, POLICY),
        whole(&asked),
        "older policy"
    );
}
