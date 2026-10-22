use ring::signature::{Ed25519KeyPair, KeyPair};
use tessari_oauth_types::base64url;

use super::{Hint, HintRefused, read_hint};
use crate::jose::{Algorithm, VerifyingKey};

const ISSUER: &str = "https://id.example.com/acme";
/// The tenant's signing key (RFC 8037 §A.1).
const ISSUER_SEED: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const ID_TOKEN_HEADER: &str = r#"{"typ":"JWT","alg":"EdDSA","kid":"k1"}"#;
/// An ID token that expired long ago: a hint is read whatever its age.
const CLAIMS: &str = concat!(
    r#"{"iss":"https://id.example.com/acme","sub":"pairwise-sub","aud":"portal","#,
    r#""exp":1000,"iat":700,"auth_time":690,"sid":"session-1"}"#
);

fn pair(seed: &[u8]) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(seed).expect("a seed is a key")
}

fn issuer_pair() -> Ed25519KeyPair {
    pair(&base64url::decode(ISSUER_SEED).expect("RFC seed"))
}

fn keys() -> Vec<VerifyingKey> {
    let jwk = format!(
        r#"{{"kid":"k1","kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
        base64url::encode(issuer_pair().public_key().as_ref())
    );
    vec![VerifyingKey::from_jwk(&jwk, Algorithm::EdDsa).expect("a public key")]
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

fn read(token: &str) -> Result<Hint, HintRefused> {
    read_hint(token, ISSUER, Algorithm::EdDsa, &keys())
}

#[test]
fn an_id_token_of_this_issuer_names_its_client_subject_and_session_however_old() {
    assert_eq!(
        read(&signed(&issuer_pair(), ID_TOKEN_HEADER, CLAIMS)),
        Ok(Hint {
            client_id: "portal".to_owned(),
            subject: "pairwise-sub".to_owned(),
            session_id: "session-1".to_owned(),
        })
    );
}

#[test]
fn a_hint_this_issuer_did_not_sign_is_refused() {
    let forged = signed(&pair(&[9; 32]), ID_TOKEN_HEADER, CLAIMS);
    assert_eq!(read(&forged), Err(HintRefused::Unverified));
    assert_eq!(read("not a token"), Err(HintRefused::Unverified));
}

#[test]
fn an_access_token_or_a_token_without_a_session_is_not_an_id_token() {
    let access = signed(
        &issuer_pair(),
        r#"{"typ":"at+jwt","alg":"EdDSA","kid":"k1"}"#,
        CLAIMS,
    );
    assert_eq!(read(&access), Err(HintRefused::NotAnIdToken));
    let sessionless = signed(
        &issuer_pair(),
        ID_TOKEN_HEADER,
        &CLAIMS.replace(r#","sid":"session-1""#, ""),
    );
    assert_eq!(read(&sessionless), Err(HintRefused::NotAnIdToken));
}

#[test]
fn a_hint_issued_for_another_tenant_is_refused() {
    let elsewhere = signed(
        &issuer_pair(),
        ID_TOKEN_HEADER,
        &CLAIMS.replace("/acme", "/globex"),
    );
    assert_eq!(read(&elsewhere), Err(HintRefused::OtherIssuer));
}
