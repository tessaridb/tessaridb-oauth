use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use tessari_oauth_constants::CLOCK_SKEW_SECS;
use tessari_oauth_types::{ErrorCode, Timestamp, base64url};

use super::{Access, Expected, Presented, verify};
use crate::Reason;
use crate::jose::{Algorithm, VerifyingKey};
use crate::token::Refusal;

const NOW: u64 = 1_800_000_000;
const ISSUER: &str = "https://id.example.com/acme";
const USERINFO: &str = "https://id.example.com/acme/oauth2/userinfo";
const TARGET: &str = "https://id.example.com/acme/oauth2/userinfo";
/// The tenant's signing key (RFC 8037 §A.1) and a client's DPoP key.
const ISSUER_SEED: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const CLIENT_SEED: [u8; 32] = [7; 32];

fn pair(seed: &[u8]) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(seed).expect("a seed is a key")
}

fn issuer_pair() -> Ed25519KeyPair {
    pair(&base64url::decode(ISSUER_SEED).expect("RFC seed"))
}

fn jwk(pair: &Ed25519KeyPair) -> String {
    format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
        base64url::encode(pair.public_key().as_ref())
    )
}

fn issuer_keys() -> Vec<VerifyingKey> {
    let jwk = jwk(&issuer_pair()).replacen('{', r#"{"kid":"k1","#, 1);
    vec![VerifyingKey::from_jwk(&jwk, Algorithm::EdDsa).expect("a public key")]
}

fn client_thumbprint() -> String {
    VerifyingKey::from_jwk(&jwk(&pair(&CLIENT_SEED)), Algorithm::EdDsa)
        .expect("a public key")
        .thumbprint()
        .as_str()
        .to_owned()
}

fn signed(pair: &Ed25519KeyPair, header: &str, claims: &str) -> String {
    let input = format!(
        "{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(claims.as_bytes())
    );
    format!(
        "{input}.{}",
        base64url::encode(pair.sign(input.as_bytes()).as_ref())
    )
}

const HEADER: &str = r#"{"typ":"at+jwt","alg":"EdDSA","kid":"k1"}"#;

/// The claims of an access token for UserInfo with `openid`, issued now, with `replace` applied.
fn claims(replace: &[(&str, &str)]) -> String {
    let mut body = format!(
        r#"{{"iss":"{ISSUER}","exp":{exp},"aud":"{USERINFO}","sub":"pw-1","client_id":"portal","iat":{NOW},"jti":"t-1","scope":"openid profile"}}"#,
        exp = NOW + 300
    );
    for (from, to) in replace {
        body = body.replacen(from, to, 1);
    }
    body
}

fn token(replace: &[(&str, &str)]) -> String {
    signed(&issuer_pair(), HEADER, &claims(replace))
}

/// A token bound to the client's DPoP key.
fn bound() -> String {
    let cnf = format!(r#","cnf":{{"jkt":"{}"}}}}"#, client_thumbprint());
    let body = claims(&[]);
    let body = format!("{}{cnf}", body.strip_suffix('}').expect("an object"));
    signed(&issuer_pair(), HEADER, &body)
}

/// A proof by `key` for a GET to UserInfo now, carrying the hash of `token`.
fn proof(key: &Ed25519KeyPair, token: &str) -> String {
    let ath = base64url::encode(Sha256::digest(token.as_bytes()).as_slice());
    signed(
        key,
        &format!(r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{}}}"#, jwk(key)),
        &format!(r#"{{"jti":"p-1","htm":"GET","htu":"{TARGET}","iat":{NOW},"ath":"{ath}"}}"#),
    )
}

fn check_at(presented: Presented<'_>, now: u64) -> Result<Access, Refusal> {
    let keys = issuer_keys();
    let expected = Expected {
        issuer: ISSUER,
        audience: USERINFO,
        algorithm: Algorithm::EdDsa,
        keys: &keys,
        method: "GET",
        target: TARGET,
    };
    verify(presented, &expected, Timestamp::from_unix_secs(now))
}

fn check(presented: Presented<'_>) -> Result<Access, Refusal> {
    check_at(presented, NOW)
}

fn refused(error: ErrorCode, reason: Reason) -> Result<Access, Refusal> {
    Err(Refusal { error, reason })
}

fn invalid(reason: Reason) -> Result<Access, Refusal> {
    refused(ErrorCode::InvalidToken, reason)
}

#[test]
fn a_bearer_token_for_userinfo_with_openid_speaks_for_its_subject() {
    assert_eq!(
        check(Presented::Bearer(&token(&[]))),
        Ok(Access {
            subject: "pw-1".to_owned(),
            client_id: "portal".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            proof: None,
        })
    );
}

#[test]
fn a_token_the_tenant_did_not_sign_under_its_algorithm_is_invalid() {
    let good = token(&[]);
    let (input, _) = good.rsplit_once('.').expect("three segments");
    let forged_by_client = signed(&pair(&CLIENT_SEED), HEADER, &claims(&[]));
    for presented in [
        format!("{input}.{}", base64url::encode(&[0; 64])),
        signed(
            &issuer_pair(),
            r#"{"typ":"at+jwt","alg":"EdDSA","kid":"k2"}"#,
            &claims(&[]),
        ),
        signed(
            &issuer_pair(),
            r#"{"typ":"at+jwt","alg":"ES256","kid":"k1"}"#,
            &claims(&[]),
        ),
        format!(
            "{}.{}.",
            base64url::encode(br#"{"typ":"at+jwt","alg":"none"}"#),
            base64url::encode(claims(&[]).as_bytes())
        ),
        forged_by_client,
        "not a token".to_owned(),
    ] {
        assert_eq!(
            check(Presented::Bearer(&presented)),
            invalid(Reason::AccessTokenUnverified),
            "{presented}"
        );
    }
}

#[test]
fn only_an_access_token_is_an_access_token() {
    for header in [
        r#"{"typ":"JWT","alg":"EdDSA","kid":"k1"}"#,
        r#"{"alg":"EdDSA","kid":"k1"}"#,
        r#"{"typ":"dpop+jwt","alg":"EdDSA","kid":"k1"}"#,
    ] {
        let presented = signed(&issuer_pair(), header, &claims(&[]));
        assert_eq!(
            check(Presented::Bearer(&presented)),
            invalid(Reason::AccessTokenType),
            "{header}"
        );
    }
    assert_eq!(
        check(Presented::Bearer(&token(&[(r#""sub":"pw-1","#, "")]))),
        invalid(Reason::AccessTokenType),
        "no subject"
    );
}

#[test]
fn another_tenants_token_or_another_resources_is_refused() {
    assert_eq!(
        check(Presented::Bearer(&token(&[(
            ISSUER,
            "https://id.example.com/globex"
        )]))),
        invalid(Reason::AccessTokenIssuer)
    );
    assert_eq!(
        check(Presented::Bearer(&token(&[(
            USERINFO,
            "https://api.example.com/"
        )]))),
        invalid(Reason::AccessTokenAudience)
    );
}

#[test]
fn an_expired_token_or_one_from_the_future_is_refused_beyond_the_skew() {
    let presented = token(&[]);
    let expiry = NOW + 300;
    assert!(check_at(Presented::Bearer(&presented), expiry + CLOCK_SKEW_SECS - 1).is_ok());
    assert_eq!(
        check_at(Presented::Bearer(&presented), expiry + CLOCK_SKEW_SECS),
        invalid(Reason::AccessTokenTime)
    );
    assert!(check_at(Presented::Bearer(&presented), NOW - CLOCK_SKEW_SECS).is_ok());
    assert_eq!(
        check_at(Presented::Bearer(&presented), NOW - CLOCK_SKEW_SECS - 1),
        invalid(Reason::AccessTokenTime)
    );
}

#[test]
fn a_token_without_openid_lacks_the_scope_userinfo_requires() {
    assert_eq!(
        check(Presented::Bearer(&token(&[(
            "openid profile",
            "profile notes:read"
        )]))),
        refused(ErrorCode::InsufficientScope, Reason::ScopeWithoutOpenId)
    );
}

#[test]
fn a_bound_token_needs_the_dpop_scheme_and_a_proof_by_its_key_over_it() {
    let token = bound();
    let client = pair(&CLIENT_SEED);
    let with = |proof: Option<&str>| {
        check(Presented::Dpop {
            token: &token,
            proof,
        })
    };
    let answered = with(Some(&proof(&client, &token))).expect("a bound token with its proof");
    assert_eq!(answered.subject, "pw-1");
    assert_eq!(
        answered
            .proof
            .map(|used| used.thumbprint.as_str().to_owned()),
        Some(client_thumbprint())
    );
    assert_eq!(
        check(Presented::Bearer(&token)),
        invalid(Reason::AccessTokenBinding),
        "bound, presented as a bearer token"
    );
    assert_eq!(
        with(Some(&proof(&issuer_pair(), &token))),
        invalid(Reason::AccessTokenBinding),
        "a proof by another key"
    );
    assert_eq!(
        with(None),
        refused(ErrorCode::InvalidDpopProof, Reason::DpopMissing)
    );
    assert_eq!(
        with(Some(&proof(&client, "another token"))),
        refused(ErrorCode::InvalidDpopProof, Reason::DpopClaims),
        "a proof over another token"
    );
    let unbound = self::token(&[]);
    assert_eq!(
        check(Presented::Dpop {
            token: &unbound,
            proof: Some(&proof(&client, &unbound)),
        }),
        invalid(Reason::AccessTokenBinding),
        "an unbound token under DPoP"
    );
}
