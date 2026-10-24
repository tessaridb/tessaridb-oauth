use ring::signature::Ed25519KeyPair;
use tessari_oauth_types::{ClientId, ErrorCode, Timestamp, base64url};

use super::{AssertionUse, verify};
use crate::Reason;
use crate::clients::{AuthMethod, ClientRegistration};
use crate::fixtures::{ACME_ISSUER, REDIRECT, acme, client};
use crate::jose::{Algorithm, VerifyingKey};
use crate::token::Refusal;

/// RFC 8037 §A.1: the Ed25519 private key `d` and its public `x`.
const SEED: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const PUBLIC_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
const NOW: u64 = 1_800_000_000;

fn confidential() -> ClientRegistration {
    let mut registration = client(acme(), "svc", &[REDIRECT]);
    registration.auth_method = AuthMethod::PrivateKeyJwt(Algorithm::EdDsa);
    registration.keys =
        vec![VerifyingKey::from_jwk(PUBLIC_JWK, Algorithm::EdDsa).expect("RFC key")];
    registration
}

/// A compact JWS of `claims` under `header`, signed with the RFC key.
fn signed(header: &str, claims: &str) -> String {
    let seed = base64url::decode(SEED).expect("RFC seed");
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("RFC seed is a key");
    let input = format!(
        "{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(claims.as_bytes())
    );
    let signature = pair.sign(input.as_bytes());
    format!("{input}.{}", base64url::encode(signature.as_ref()))
}

fn claims(aud: &str, exp: u64, extra: &str) -> String {
    format!(r#"{{"iss":"svc","sub":"svc","aud":{aud},"exp":{exp},"jti":"a-1"{extra}}}"#)
}

fn good() -> String {
    claims(&format!("{ACME_ISSUER:?}"), NOW + 60, "")
}

const HEADER: &str = r#"{"alg":"EdDSA","kid":"k1","typ":"client-authentication+jwt"}"#;

fn check(compact: &str) -> Result<AssertionUse, Refusal> {
    verify(
        compact,
        &confidential(),
        ACME_ISSUER,
        Timestamp::from_unix_secs(NOW),
    )
}

fn refused(reason: Reason) -> Result<AssertionUse, Refusal> {
    Err(Refusal {
        error: ErrorCode::InvalidClient,
        reason,
    })
}

#[test]
fn a_valid_assertion_yields_its_jti_and_expiry_for_the_single_use_record() {
    assert_eq!(
        check(&signed(HEADER, &good())),
        Ok(AssertionUse {
            client_id: ClientId::parse("svc").expect("fixture"),
            jti: "a-1".to_owned(),
            expires_at: Timestamp::from_unix_secs(NOW + 60),
        })
    );
    for header in [r#"{"alg":"EdDSA"}"#, r#"{"alg":"EdDSA","typ":"JWT"}"#] {
        assert!(check(&signed(header, &good())).is_ok(), "{header}");
    }
}

#[test]
fn a_signature_the_registration_does_not_vouch_for_is_refused() {
    let tampered = signed(HEADER, &good()).replacen("eyJ", "eyK", 1);
    assert_eq!(check(&tampered), refused(Reason::AssertionSignature));
    assert_eq!(
        check(&signed(r#"{"alg":"ES256"}"#, &good())),
        refused(Reason::AssertionSignature)
    );
    assert_eq!(
        check(&signed(r#"{"alg":"EdDSA","kid":"k2"}"#, &good())),
        refused(Reason::AssertionSignature)
    );
}

#[test]
fn another_jwt_type_is_refused_but_an_absent_one_is_not() {
    for typ in ["dpop+jwt", "at+jwt", "client-authentication+JWT"] {
        let header = format!(r#"{{"alg":"EdDSA","typ":"{typ}"}}"#);
        assert_eq!(
            check(&signed(&header, &good())),
            refused(Reason::AssertionClaims),
            "{typ}"
        );
    }
}

#[test]
fn issuer_and_subject_must_both_be_the_client() {
    for (iss, sub) in [("other", "svc"), ("svc", "other"), ("other", "other")] {
        let body = good()
            .replace(r#""iss":"svc""#, &format!(r#""iss":"{iss}""#))
            .replace(r#""sub":"svc""#, &format!(r#""sub":"{sub}""#));
        assert_eq!(
            check(&signed(HEADER, &body)),
            refused(Reason::AssertionClaims),
            "{iss} {sub}"
        );
    }
}

#[test]
fn the_audience_is_this_tenants_issuer_and_nothing_else() {
    let issuer = format!("{ACME_ISSUER:?}");
    assert!(
        check(&signed(
            HEADER,
            &claims(&format!("[{issuer}]"), NOW + 60, "")
        ))
        .is_ok()
    );
    for aud in [
        format!("{:?}", format!("{ACME_ISSUER}/token")),
        r#""https://id.example.com/globex""#.to_owned(),
        format!("[{issuer},\"https://elsewhere.example\"]"),
        "[]".to_owned(),
        format!("{:?}", format!("{ACME_ISSUER}/")),
    ] {
        assert_eq!(
            check(&signed(HEADER, &claims(&aud, NOW + 60, ""))),
            refused(Reason::AssertionAudience),
            "{aud}"
        );
    }
}

#[test]
fn time_bounds_allow_seconds_of_skew_and_no_more() {
    let aud = format!("{ACME_ISSUER:?}");
    for (exp, extra) in [
        (NOW + 300, ""),
        (NOW - 9, ""),
        (NOW + 60, &format!(r#","nbf":{}"#, NOW + 10)),
    ] {
        assert!(
            check(&signed(HEADER, &claims(&aud, exp, extra))).is_ok(),
            "{exp} {extra}"
        );
    }
    for (exp, extra) in [
        (NOW - 10, String::new()),
        (NOW + 311, String::new()),
        (NOW + 60, format!(r#","nbf":{}"#, NOW + 11)),
    ] {
        assert_eq!(
            check(&signed(HEADER, &claims(&aud, exp, &extra))),
            refused(Reason::AssertionTime),
            "{exp} {extra}"
        );
    }
}

#[test]
fn a_jti_is_required_and_bounded() {
    let aud = format!("{ACME_ISSUER:?}");
    let long = "j".repeat(257);
    for body in [
        claims(&aud, NOW + 60, "").replace(r#","jti":"a-1""#, ""),
        claims(&aud, NOW + 60, "").replace(r#""jti":"a-1""#, r#""jti":"""#),
        claims(&aud, NOW + 60, "").replace("a-1", &long),
    ] {
        assert_eq!(
            check(&signed(HEADER, &body)),
            refused(Reason::AssertionClaims),
            "{body}"
        );
    }
    let at_bound = claims(&aud, NOW + 60, "").replace("a-1", &"j".repeat(256));
    assert!(check(&signed(HEADER, &at_bound)).is_ok());
}

mod at_the_token_endpoint {
    use super::*;
    use crate::fixtures::Directory;
    use crate::token::{Endpoint, PresentedAuth, authenticate_client, read};

    const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    fn endpoint() -> Endpoint {
        Endpoint {
            tenant: acme(),
            issuer: ACME_ISSUER.to_owned(),
            now: Timestamp::from_unix_secs(NOW),
        }
    }

    fn directory() -> Directory {
        Directory(vec![confidential(), client(acme(), "app", &[REDIRECT])])
    }

    fn params(client_id: &str, kind: Option<&str>, assertion: Option<&str>) -> crate::Params {
        let mut pairs = vec![("client_id", client_id.to_owned())];
        pairs.extend(kind.map(|kind| ("client_assertion_type", kind.to_owned())));
        pairs.extend(assertion.map(|value| ("client_assertion", value.to_owned())));
        read(pairs).expect("no repeats")
    }

    fn authenticate(
        presented: PresentedAuth,
        params: &crate::Params,
    ) -> Result<Option<AssertionUse>, Refusal> {
        authenticate_client(&endpoint(), &directory(), presented, params)
            .map(|authenticated| authenticated.assertion)
    }

    #[test]
    fn a_pinned_private_key_jwt_client_authenticates_with_its_assertion() {
        let assertion = signed(HEADER, &good());
        let used = authenticate(
            PresentedAuth::PrivateKeyJwt,
            &params("svc", Some(ASSERTION_TYPE), Some(&assertion)),
        )
        .expect("authenticated");
        assert_eq!(used.map(|used| used.jti), Some("a-1".to_owned()));
    }

    #[test]
    fn an_assertion_sent_without_client_id_names_its_client_by_its_subject() {
        // RFC 7521 §4.2: `client_id` is optional beside an assertion, whose subject identifies the client.
        let assertion = signed(HEADER, &good());
        let pairs = vec![
            ("client_assertion_type", ASSERTION_TYPE.to_owned()),
            ("client_assertion", assertion),
        ];
        let used = authenticate(
            PresentedAuth::PrivateKeyJwt,
            &read(pairs).expect("no repeats"),
        )
        .expect("authenticated");
        assert_eq!(used.map(|used| used.jti), Some("a-1".to_owned()));
    }

    #[test]
    fn the_pinned_method_holds_in_both_directions() {
        let not_pinned = Err(Refusal {
            error: ErrorCode::InvalidClient,
            reason: Reason::AuthMethodNotPinned,
        });
        assert_eq!(
            authenticate(PresentedAuth::None, &params("svc", None, None)),
            not_pinned
        );
        let assertion = signed(HEADER, &good().replace("svc", "app"));
        assert_eq!(
            authenticate(
                PresentedAuth::PrivateKeyJwt,
                &params("app", Some(ASSERTION_TYPE), Some(&assertion))
            ),
            not_pinned
        );
    }

    #[test]
    fn the_assertion_type_and_the_assertion_are_both_required() {
        let assertion = signed(HEADER, &good());
        for (kind, value, reason) in [
            (
                Some("urn:ietf:params:oauth:client-assertion-type:saml2-bearer"),
                Some(assertion.as_str()),
                Reason::MalformedParameter,
            ),
            (None, Some(assertion.as_str()), Reason::MissingParameter),
            (Some(ASSERTION_TYPE), None, Reason::MissingParameter),
        ] {
            assert_eq!(
                authenticate(PresentedAuth::PrivateKeyJwt, &params("svc", kind, value)),
                Err(Refusal {
                    error: ErrorCode::InvalidClient,
                    reason
                }),
                "{kind:?} {value:?}"
            );
        }
    }
}
