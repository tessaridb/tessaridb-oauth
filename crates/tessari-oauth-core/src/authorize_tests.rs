use tessari_oauth_types::ErrorCode;

use super::{Refusal, validate};
use crate::Reason;
use std::collections::BTreeSet;

use tessari_oauth_types::Resource;

use crate::fixtures::{
    ACME_ISSUER, CHALLENGE, Directory, NOTES, REDIRECT, acme, client, directory,
};

/// A request every check accepts; each row below changes exactly one thing from it.
pub(super) fn valid() -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_owned()),
        ("client_id", "app".to_owned()),
        ("redirect_uri", REDIRECT.to_owned()),
        ("scope", "openid notes:read".to_owned()),
        ("state", "af0ifjsldkj".to_owned()),
        ("code_challenge", CHALLENGE.to_owned()),
        ("code_challenge_method", "S256".to_owned()),
    ]
}

pub(super) fn with(name: &'static str, value: &str) -> Vec<(&'static str, String)> {
    let mut pairs: Vec<_> = valid()
        .into_iter()
        .filter(|(key, _)| *key != name)
        .collect();
    pairs.push((name, value.to_owned()));
    pairs
}

fn without(name: &str) -> Vec<(&'static str, String)> {
    valid()
        .into_iter()
        .filter(|(key, _)| *key != name)
        .collect()
}

pub(super) fn run(
    pairs: Vec<(&'static str, String)>,
) -> Result<super::AuthorizationRequest, Refusal> {
    validate(&acme(), ACME_ISSUER, &directory(), pairs)
}

fn rendered(pairs: Vec<(&'static str, String)>) -> Reason {
    match run(pairs) {
        Err(Refusal::RenderAtServer { reason, .. }) => reason,
        other => panic!("expected a refusal rendered at the server, got {other:?}"),
    }
}

pub(super) fn redirected(pairs: Vec<(&'static str, String)>) -> (ErrorCode, Reason) {
    match run(pairs) {
        Err(Refusal::RedirectToClient {
            redirect_uri,
            error,
            state,
            iss,
            reason,
        }) => {
            assert_eq!(
                redirect_uri, REDIRECT,
                "an error travels only to the registered URI"
            );
            assert_eq!(
                state.as_deref(),
                Some("af0ifjsldkj"),
                "state is echoed unchanged"
            );
            assert_eq!(
                iss, ACME_ISSUER,
                "the issuer travels with every redirected error"
            );
            (error, reason)
        }
        other => panic!("expected a refusal redirected to the client, got {other:?}"),
    }
}

#[test]
fn a_valid_request_passes_with_its_bindings() {
    let request = run(valid()).expect("the baseline request is valid");
    assert_eq!(request.client_id.as_str(), "app");
    assert_eq!(request.redirect_uri, REDIRECT);
    assert_eq!(
        request.scopes.iter().collect::<Vec<_>>(),
        ["notes:read", "openid"]
    );
    assert_eq!(request.challenge.as_str(), CHALLENGE);
    assert_eq!(request.state.as_deref(), Some("af0ifjsldkj"));
}

#[test]
fn a1_an_unknown_client_is_refused_at_the_server() {
    assert_eq!(rendered(with("client_id", "nobody")), Reason::UnknownClient);
    assert_eq!(rendered(without("client_id")), Reason::MissingParameter);
}

#[test]
fn a2_a_client_of_another_tenant_is_unknown_here() {
    assert_eq!(rendered(with("client_id", "other")), Reason::UnknownClient);
}

#[test]
fn a3_a_redirect_uri_the_client_did_not_register_is_refused_at_the_server() {
    for presented in [
        "https://evil.example/callback",
        "https://app.example.com/callback/extra",
        "https://app.example.com/callback?x=1",
        "https://app.example.com/Callback",
        "https://app.example.com/callback/",
    ] {
        assert_eq!(
            rendered(with("redirect_uri", presented)),
            Reason::UnregisteredRedirectUri,
            "{presented}"
        );
    }
}

#[test]
fn a3_an_invalid_scope_with_an_unregistered_redirect_is_still_not_redirected() {
    // The ordering row: a later failure must not reach a URI an earlier check would have refused.
    let mut pairs = with("redirect_uri", "https://evil.example/callback");
    pairs.retain(|(key, _)| *key != "scope");
    pairs.push(("scope", "admin".to_owned()));
    assert_eq!(rendered(pairs), Reason::UnregisteredRedirectUri);
}

#[test]
fn a4_omitting_the_redirect_uri_is_refused_when_several_are_registered() {
    let mut pairs = without("redirect_uri");
    pairs.retain(|(key, _)| *key != "client_id");
    pairs.push(("client_id", "multi".to_owned()));
    assert_eq!(rendered(pairs), Reason::RedirectUriRequired);
}

#[test]
fn a4_omitting_the_redirect_uri_uses_the_only_registered_one() {
    let request = run(without("redirect_uri")).expect("one registered URI is the default");
    assert_eq!(request.redirect_uri, REDIRECT);
}

#[test]
fn a_native_client_redirects_to_its_loopback_uri_on_any_port() {
    let mut pairs = with("redirect_uri", "http://127.0.0.1:51004/callback");
    pairs.retain(|(key, _)| *key != "client_id");
    pairs.push(("client_id", "native".to_owned()));
    let request = run(pairs).expect("the loopback port varies");
    assert_eq!(
        request.redirect_uri, "http://127.0.0.1:51004/callback",
        "the presented URI is kept for redemption"
    );
}

#[test]
fn a5_a_response_type_other_than_code_is_redirected() {
    for response_type in ["token", "code id_token", "id_token"] {
        assert_eq!(
            redirected(with("response_type", response_type)),
            (
                ErrorCode::UnsupportedResponseType,
                Reason::UnsupportedResponseType
            ),
            "{response_type}"
        );
    }
    assert_eq!(
        redirected(without("response_type")),
        (ErrorCode::InvalidRequest, Reason::MissingParameter)
    );
}

#[test]
fn a6_a_missing_or_malformed_challenge_is_redirected() {
    assert_eq!(
        redirected(without("code_challenge")),
        (ErrorCode::InvalidRequest, Reason::MissingParameter)
    );
    assert_eq!(
        redirected(with("code_challenge", "short")),
        (ErrorCode::InvalidRequest, Reason::MalformedParameter)
    );
}

#[test]
fn a7_any_challenge_method_but_s256_is_redirected() {
    for method in ["plain", "s256", "S512"] {
        assert_eq!(
            redirected(with("code_challenge_method", method)),
            (
                ErrorCode::InvalidRequest,
                Reason::UnsupportedChallengeMethod
            ),
            "{method}"
        );
    }
    // Absent means `plain` under RFC 7636 §4.3, so it is refused rather than defaulted.
    assert_eq!(
        redirected(without("code_challenge_method")),
        (
            ErrorCode::InvalidRequest,
            Reason::UnsupportedChallengeMethod
        )
    );
}

#[test]
fn a8_a_scope_beyond_the_ceiling_or_absent_or_malformed_is_redirected() {
    assert_eq!(
        redirected(with("scope", "openid notes:write")),
        (ErrorCode::InvalidScope, Reason::ScopeBeyondCeiling)
    );
    assert_eq!(
        redirected(without("scope")),
        (ErrorCode::InvalidScope, Reason::MissingParameter)
    );
    assert_eq!(
        redirected(with("scope", "openid  profile")),
        (ErrorCode::InvalidScope, Reason::MalformedParameter)
    );
}

#[test]
fn a9_a_repeated_parameter_is_refused_at_the_server() {
    let mut pairs = valid();
    pairs.push(("redirect_uri", "https://evil.example/callback".to_owned()));
    assert_eq!(rendered(pairs), Reason::DuplicateParameter);
}

#[test]
fn a2_a_directory_returning_another_tenants_client_is_still_refused() {
    let pairs = with("client_id", "other");
    match validate(
        &acme(),
        ACME_ISSUER,
        &crate::fixtures::CarelessDirectory,
        pairs,
    ) {
        Err(Refusal::RenderAtServer { reason, .. }) => assert_eq!(reason, Reason::UnknownClient),
        other => panic!("expected a refusal rendered at the server, got {other:?}"),
    }
}

fn resources(names: &[&str]) -> BTreeSet<Resource> {
    names
        .iter()
        .map(|name| Resource::parse(*name).expect("a resource"))
        .collect()
}

#[test]
fn a10_the_resource_is_the_one_named_or_the_only_one_registered() {
    let request = run(valid()).expect("valid without a resource");
    assert_eq!(
        request.resources,
        resources(&[NOTES]),
        "the only registered one"
    );
    let named = run(with("resource", NOTES)).expect("valid with its resource");
    assert_eq!(named.resources, resources(&[NOTES]));
}

#[test]
fn a10_a_resource_the_client_did_not_register_is_redirected() {
    for named in ["https://files.example.com/", "not a uri"] {
        assert_eq!(
            redirected(with("resource", named)),
            (ErrorCode::InvalidTarget, Reason::TargetNotGranted),
            "{named}"
        );
    }
}

#[test]
fn a10_no_resource_named_where_several_are_registered_is_redirected() {
    let mut several = client(acme(), "app", &[REDIRECT]);
    several.resources = resources(&[NOTES, "https://files.example.com/"]);
    match validate(&acme(), ACME_ISSUER, &Directory(vec![several]), valid()) {
        Err(Refusal::RedirectToClient { error, reason, .. }) => {
            assert_eq!(
                (error, reason),
                (ErrorCode::InvalidTarget, Reason::TargetUnnamed)
            );
        }
        other => panic!("expected a redirected refusal, got {other:?}"),
    }
}

#[test]
fn a_nonce_is_carried_unchanged_and_is_absent_when_not_sent() {
    assert_eq!(run(valid()).expect("valid").nonce, None);
    assert_eq!(
        run(with("nonce", "n-0S6_WzA2Mj"))
            .expect("valid")
            .nonce
            .as_deref(),
        Some("n-0S6_WzA2Mj")
    );
}
