use serde_json::Value;
use tessari_oauth_types::{Algorithm, Timestamp};

use super::{IssuerRefused, metadata};
use crate::clients::{AuthMethod, GrantType};
use crate::fixtures::{ACME_ISSUER, Directory, REDIRECT, acme, client};
use crate::token::{Endpoint, PresentedAuth, authenticate_client, require_grant};
use crate::{Params, Reason};

fn document() -> Value {
    let rendered = metadata(ACME_ISSUER, Algorithm::Es256).expect("a valid issuer");
    serde_json::to_value(&rendered).expect("serialisable")
}

fn names(document: &Value, field: &str) -> Vec<String> {
    document[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} is an array"))
        .iter()
        .map(|name| name.as_str().expect("a string").to_owned())
        .collect()
}

#[test]
fn the_issuer_and_the_endpoints_are_the_issuer_byte_for_byte_and_its_fixed_paths() {
    let document = document();
    assert_eq!(document["issuer"], ACME_ISSUER);
    assert_eq!(
        document["authorization_endpoint"],
        "https://id.example.com/acme/oauth2/authorize"
    );
    assert_eq!(
        document["token_endpoint"],
        "https://id.example.com/acme/oauth2/token"
    );
    assert_eq!(
        document["jwks_uri"],
        "https://id.example.com/acme/oauth2/jwks"
    );
}

#[test]
fn an_issuer_that_is_not_a_plain_https_url_is_refused() {
    for issuer in [
        "http://id.example.com/acme",
        "https://id.example.com/acme?tenant=acme",
        "https://id.example.com/acme#top",
        "https://id.example.com/acme/",
        "https://user@id.example.com/acme",
        // Valid URLs whose serialisation differs from the input, so a token's `iss` could not equal it.
        "https://ID.example.com/acme",
        "https://id.example.com/x/../acme",
        "not a url",
    ] {
        assert_eq!(
            metadata(issuer, Algorithm::Es256).err(),
            Some(IssuerRefused),
            "{issuer}"
        );
    }
}

#[test]
fn only_the_code_flow_with_s256_and_the_iss_response_parameter_are_advertised() {
    let document = document();
    assert_eq!(names(&document, "response_types_supported"), ["code"]);
    assert_eq!(
        names(&document, "code_challenge_methods_supported"),
        ["S256"]
    );
    assert_eq!(
        document["authorization_response_iss_parameter_supported"],
        true
    );
}

#[test]
fn every_advertised_grant_is_one_the_token_endpoint_redeems() {
    let advertised = names(&document(), "grant_types_supported");
    assert_eq!(
        advertised,
        ["authorization_code", "refresh_token", "client_credentials"]
    );
    let mut registered = client(acme(), "app", &[REDIRECT]);
    registered.grant_types = GrantType::ALL.to_vec();
    for name in &advertised {
        let params = Params::from_pairs([("grant_type", name.as_str())]).expect("one pair");
        let grant = require_grant(&params, &registered).expect("redeemed");
        assert_eq!(grant.name(), name);
    }
}

/// The verdict the token endpoint gives a client pinned to `method` that presents it without a credential.
fn verdict(method: AuthMethod, presented: PresentedAuth) -> Result<(), Reason> {
    let mut registered = client(acme(), "app", &[REDIRECT]);
    registered.auth_method = method;
    let endpoint = Endpoint {
        tenant: acme(),
        issuer: ACME_ISSUER.to_owned(),
        now: Timestamp::from_unix_secs(1_800_000_000),
    };
    let params = Params::from_pairs([("client_id", "app")]).expect("one pair");
    authenticate_client(&endpoint, &Directory(vec![registered]), presented, &params)
        .map(|_| ())
        .map_err(|refusal| refusal.reason)
}

#[test]
fn exactly_the_auth_methods_the_token_endpoint_verifies_are_advertised() {
    let advertised = names(&document(), "token_endpoint_auth_methods_supported");
    assert_eq!(advertised, ["none", "private_key_jwt"]);
    let cases = [
        (AuthMethod::None, PresentedAuth::None),
        (
            AuthMethod::ClientSecretBasic,
            PresentedAuth::ClientSecretBasic,
        ),
        (
            AuthMethod::ClientSecretPost,
            PresentedAuth::ClientSecretPost,
        ),
        (
            AuthMethod::PrivateKeyJwt(Algorithm::Es256),
            PresentedAuth::PrivateKeyJwt,
        ),
    ];
    for (method, presented) in cases {
        // A method the endpoint verifies either passes or fails on the missing credential; only an unverifiable
        // one is refused as not pinned.
        let verified = verdict(method, presented) != Err(Reason::AuthMethodNotPinned);
        assert_eq!(
            advertised.iter().any(|name| name == method.name()),
            verified,
            "{method:?}"
        );
    }
}

#[test]
fn the_signing_algorithms_are_the_ones_the_jose_checks_accept() {
    let document = document();
    let all: Vec<&str> = Algorithm::ALL
        .iter()
        .map(|algorithm| algorithm.name())
        .collect();
    assert_eq!(all, ["EdDSA", "ES256"]);
    assert_eq!(
        names(
            &document,
            "token_endpoint_auth_signing_alg_values_supported"
        ),
        all
    );
    let dpop: Vec<&str> = crate::dpop::ALGORITHMS
        .iter()
        .map(|algorithm| algorithm.name())
        .collect();
    assert_eq!(names(&document, "dpop_signing_alg_values_supported"), dpop);
}

#[test]
fn the_revocation_endpoint_is_advertised_with_the_token_endpoints_auth_methods() {
    let document = document();
    assert_eq!(
        document["revocation_endpoint"],
        "https://id.example.com/acme/oauth2/revoke"
    );
    assert_eq!(
        names(&document, "revocation_endpoint_auth_methods_supported"),
        names(&document, "token_endpoint_auth_methods_supported")
    );
    assert_eq!(
        names(&document, "revocation_endpoint_auth_methods_supported"),
        ["none", "private_key_jwt"]
    );
}

#[test]
fn pushed_authorization_requests_are_advertised_and_not_required() {
    let document = document();
    assert_eq!(
        document["pushed_authorization_request_endpoint"],
        "https://id.example.com/acme/oauth2/par"
    );
    assert_eq!(document["require_pushed_authorization_requests"], false);
}

#[test]
fn userinfo_is_advertised_under_the_issuer() {
    assert_eq!(
        document()["userinfo_endpoint"],
        "https://id.example.com/acme/oauth2/userinfo"
    );
}

#[test]
fn rp_initiated_logout_is_advertised_under_the_issuer() {
    assert_eq!(
        document()["end_session_endpoint"],
        "https://id.example.com/acme/oauth2/logout"
    );
}

#[test]
fn nothing_the_server_does_not_enforce_yet_is_advertised() {
    let document = document();
    // The ID token's subject type and algorithm are advertised now that ID tokens are issued; scopes are not yet.
    assert!(document.get("scopes_supported").is_none());
}

#[test]
fn the_openid_fields_name_the_one_subject_type_and_the_signing_algorithm() {
    let document = document();
    assert_eq!(names(&document, "subject_types_supported"), ["pairwise"]);
    assert_eq!(
        names(&document, "id_token_signing_alg_values_supported"),
        ["ES256"]
    );
    let other =
        serde_json::to_value(metadata(ACME_ISSUER, Algorithm::EdDsa).expect("a valid issuer"))
            .expect("serialisable");
    assert_eq!(
        names(&other, "id_token_signing_alg_values_supported"),
        [Algorithm::EdDsa.name()],
        "the configured algorithm, whichever it is"
    );
}
