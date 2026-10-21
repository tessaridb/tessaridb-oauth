use std::collections::BTreeSet;
use tessari_oauth_constants::AUTHORIZATION_CODE_TTL_SECS;

use tessari_oauth_types::{Challenge, ClientId, ErrorCode, Resource, ScopeSet, Timestamp, UserId};

use super::{
    Endpoint, PresentedAuth, Refusal, authenticate_client, read, redeem_code, require_grant,
};
use crate::Reason;
use crate::clients::GrantType;
use crate::codes::IssuedCode;
use crate::fixtures::{CHALLENGE, REDIRECT, VERIFIER, acme, client, directory, globex};

const ISSUED_AT: u64 = 1_800_000_000;

fn endpoint() -> Endpoint {
    Endpoint {
        tenant: acme(),
        issuer: crate::fixtures::ACME_ISSUER.to_owned(),
        now: Timestamp::from_unix_secs(ISSUED_AT),
    }
}

fn issued() -> IssuedCode {
    IssuedCode {
        tenant: acme(),
        client_id: ClientId::parse("app").expect("fixture"),
        user: UserId::parse("user-1").expect("fixture"),
        redirect_uri: REDIRECT.to_owned(),
        challenge: Challenge::parse(CHALLENGE).expect("fixture"),
        scopes: ScopeSet::parse("openid").expect("fixture"),
        resources: BTreeSet::from([resource(ORDERS)]),
        expires_at: Timestamp::from_unix_secs(ISSUED_AT + AUTHORIZATION_CODE_TTL_SECS),
    }
}

const ORDERS: &str = "https://api.example.com/orders";
const BILLING: &str = "https://api.example.com/billing";

fn resource(uri: &str) -> Resource {
    Resource::parse(uri).expect("fixture")
}

fn request() -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", "the-code".to_owned()),
        ("client_id", "app".to_owned()),
        ("redirect_uri", REDIRECT.to_owned()),
        ("code_verifier", VERIFIER.to_owned()),
    ]
}

fn with(name: &'static str, value: &str) -> Vec<(&'static str, String)> {
    let mut pairs: Vec<_> = request()
        .into_iter()
        .filter(|(key, _)| *key != name)
        .collect();
    pairs.push((name, value.to_owned()));
    pairs
}

fn without(name: &str) -> Vec<(&'static str, String)> {
    request()
        .into_iter()
        .filter(|(key, _)| *key != name)
        .collect()
}

fn just_before_expiry() -> Timestamp {
    Timestamp::from_unix_secs(ISSUED_AT + AUTHORIZATION_CODE_TTL_SECS - 1)
}

fn redeem(
    pairs: Vec<(&'static str, String)>,
    code: &IssuedCode,
    now: Timestamp,
) -> Result<super::Redemption, Refusal> {
    let params = read(pairs).expect("no repeats");
    let app = client(acme(), "app", &[REDIRECT]);
    redeem_code(&acme(), &app, &params, code, now)
}

fn grant_refusal(pairs: Vec<(&'static str, String)>, code: &IssuedCode) -> Reason {
    match redeem(pairs, code, just_before_expiry()) {
        Err(Refusal {
            error: ErrorCode::InvalidGrant,
            reason,
        }) => reason,
        other => panic!("expected invalid_grant, got {other:?}"),
    }
}

#[test]
fn a_code_redeems_with_every_binding_intact() {
    let redemption = redeem(request(), &issued(), just_before_expiry()).expect("all bindings hold");
    assert_eq!(redemption.client_id.as_str(), "app");
    assert_eq!(redemption.scopes.iter().collect::<Vec<_>>(), ["openid"]);
    assert_eq!(redemption.user.as_str(), "user-1");
    assert_eq!(
        redemption.audience.as_str(),
        ORDERS,
        "the code's only resource"
    );
}

#[test]
fn t9_the_audience_is_one_resource_the_code_was_granted_for() {
    let mut code = issued();
    code.resources = BTreeSet::from([resource(ORDERS), resource(BILLING)]);
    let named = redeem(with("resource", BILLING), &code, just_before_expiry()).expect("granted");
    assert_eq!(named.audience.as_str(), BILLING);
    for (pairs, reason) in [
        (request(), Reason::TargetUnnamed),
        (
            with("resource", "https://api.example.com/other"),
            Reason::TargetNotGranted,
        ),
        (
            with("resource", "http://api.example.com/orders"),
            Reason::TargetNotGranted,
        ),
    ] {
        assert_eq!(
            redeem(pairs, &code, just_before_expiry()),
            Err(Refusal {
                error: ErrorCode::InvalidTarget,
                reason
            })
        );
    }
}

#[test]
fn t1_a_code_issued_to_another_client_is_refused() {
    let mut code = issued();
    code.client_id = ClientId::parse("someone-else").expect("fixture");
    assert_eq!(grant_refusal(request(), &code), Reason::CodeClientMismatch);
}

#[test]
fn t2_a_redirect_uri_differing_from_the_authorization_request_is_refused() {
    for presented in [
        "https://app.example.com/callback/",
        "https://app.example.com/other",
    ] {
        assert_eq!(
            grant_refusal(with("redirect_uri", presented), &issued()),
            Reason::CodeRedirectMismatch
        );
    }
    assert_eq!(
        grant_refusal(without("redirect_uri"), &issued()),
        Reason::CodeRedirectMismatch
    );
}

#[test]
fn t3_an_absent_verifier_is_refused() {
    assert_eq!(
        grant_refusal(without("code_verifier"), &issued()),
        Reason::VerifierMissing
    );
}

#[test]
fn t4_a_wrong_verifier_is_refused() {
    let wrong = VERIFIER.replacen('d', "D", 1);
    assert_eq!(
        grant_refusal(with("code_verifier", &wrong), &issued()),
        Reason::VerifierMismatch
    );
}

#[test]
fn t5_a_code_at_or_after_its_expiry_is_refused() {
    let at_expiry = Timestamp::from_unix_secs(ISSUED_AT + AUTHORIZATION_CODE_TTL_SECS);
    assert_eq!(
        redeem(request(), &issued(), at_expiry),
        Err(Refusal {
            error: ErrorCode::InvalidGrant,
            reason: Reason::CodeExpired
        })
    );
}

#[test]
fn t6_a_code_minted_in_another_tenant_is_refused() {
    let mut code = issued();
    code.tenant = globex();
    assert_eq!(grant_refusal(request(), &code), Reason::CodeTenantMismatch);
}

#[test]
fn t7_a_public_client_presenting_a_secret_is_refused_as_not_pinned() {
    let params = read(request()).expect("no repeats");
    for presented in [
        PresentedAuth::ClientSecretBasic,
        PresentedAuth::ClientSecretPost,
        PresentedAuth::PrivateKeyJwt,
    ] {
        assert_eq!(
            authenticate_client(&endpoint(), &directory(), presented, &params),
            Err(Refusal {
                error: ErrorCode::InvalidClient,
                reason: Reason::AuthMethodNotPinned
            }),
            "{presented:?}"
        );
    }
    let found = authenticate_client(&endpoint(), &directory(), PresentedAuth::None, &params)
        .expect("pinned none");
    assert_eq!(found.client.client_id.as_str(), "app");
}

#[test]
fn t7_an_unknown_or_foreign_client_is_refused_as_invalid_client() {
    for id in ["nobody", "other"] {
        let params = read(with("client_id", id)).expect("no repeats");
        assert_eq!(
            authenticate_client(&endpoint(), &directory(), PresentedAuth::None, &params),
            Err(Refusal {
                error: ErrorCode::InvalidClient,
                reason: Reason::UnknownClient
            }),
            "{id}"
        );
    }
    let params = read(without("client_id")).expect("no repeats");
    assert_eq!(
        authenticate_client(&endpoint(), &directory(), PresentedAuth::None, &params),
        Err(Refusal {
            error: ErrorCode::InvalidClient,
            reason: Reason::MissingParameter
        })
    );
}

#[test]
fn t8_only_the_code_and_refresh_grants_exist_and_only_for_a_client_registered_for_them() {
    let app = client(acme(), "app", &[REDIRECT]);
    for (grant, expected) in [
        ("authorization_code", GrantType::AuthorizationCode),
        ("refresh_token", GrantType::RefreshToken),
    ] {
        let params = read(with("grant_type", grant)).expect("no repeats");
        assert_eq!(require_grant(&params, &app), Ok(expected), "{grant}");
    }
    let mut code_only = app.clone();
    code_only.grant_types = vec![GrantType::AuthorizationCode];
    let params = read(with("grant_type", "refresh_token")).expect("no repeats");
    assert_eq!(
        require_grant(&params, &code_only),
        Err(Refusal {
            error: ErrorCode::UnauthorizedClient,
            reason: Reason::GrantNotRegistered
        })
    );
    for grant in [
        "password",
        "implicit",
        "client_credentials",
        "REFRESH_TOKEN",
    ] {
        let params = read(with("grant_type", grant)).expect("no repeats");
        assert_eq!(
            require_grant(&params, &app),
            Err(Refusal {
                error: ErrorCode::UnsupportedGrantType,
                reason: Reason::UnsupportedGrantType
            }),
            "{grant}"
        );
    }
    let params = read(without("grant_type")).expect("no repeats");
    assert_eq!(
        require_grant(&params, &app),
        Err(Refusal {
            error: ErrorCode::InvalidRequest,
            reason: Reason::MissingParameter
        })
    );
}

#[test]
fn a_repeated_token_parameter_is_refused() {
    let mut pairs = request();
    pairs.push(("code_verifier", VERIFIER.to_owned()));
    assert_eq!(
        read(pairs),
        Err(Refusal {
            error: ErrorCode::InvalidRequest,
            reason: Reason::DuplicateParameter
        })
    );
}

#[test]
fn t6_a_directory_returning_another_tenants_client_is_still_refused() {
    let params = read(with("client_id", "other")).expect("no repeats");
    assert_eq!(
        authenticate_client(
            &endpoint(),
            &crate::fixtures::CarelessDirectory,
            PresentedAuth::None,
            &params
        ),
        Err(Refusal {
            error: ErrorCode::InvalidClient,
            reason: Reason::UnknownClient
        })
    );
}
