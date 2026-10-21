use ring::signature::Ed25519KeyPair;
use tessari_oauth_types::{ErrorCode, KeyThumbprint, Timestamp, base64url};

use super::{ProofUse, verify_proof, verify_resource_proof};
use crate::Reason;
use crate::token::Refusal;

/// RFC 9449 Figure 2: an ES256 proof for `POST https://server.example.com/token` at `iat` 1562262616.
const RFC_PROOF: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";
const RFC_IAT: u64 = 1_562_262_616;
const RFC_TARGET: &str = "https://server.example.com/token";

/// RFC 8037 §A.1 Ed25519 key, for proofs written here.
const SEED: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
/// RFC 9449's EC public key, which the Ed25519 key above did not sign with.
const OTHER_JWK: &str = r#"{"kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","crv":"P-256"}"#;

fn ed_jwk() -> String {
    format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{X}"}}"#)
}

fn signed(header: &str, claims: &str) -> String {
    let seed = base64url::decode(SEED).expect("RFC seed");
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("RFC seed is a key");
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

fn header() -> String {
    format!(r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{}}}"#, ed_jwk())
}

const NOW: u64 = 1_800_000_000;

fn claims(extra: &str) -> String {
    format!(
        r#"{{"jti":"p-1","htm":"POST","htu":"https://id.example.com/acme/token","iat":{NOW}{extra}}}"#
    )
}

fn check(proof: &str) -> Result<ProofUse, Refusal> {
    verify_proof(
        proof,
        "POST",
        "https://id.example.com/acme/token",
        Timestamp::from_unix_secs(NOW),
    )
}

fn refused(reason: Reason) -> Result<ProofUse, Refusal> {
    Err(Refusal {
        error: ErrorCode::InvalidDpopProof,
        reason,
    })
}

#[test]
fn the_rfc_proof_verifies_and_names_the_key_to_bind() {
    assert_eq!(
        verify_proof(
            RFC_PROOF,
            "POST",
            RFC_TARGET,
            Timestamp::from_unix_secs(RFC_IAT + 10)
        ),
        Ok(ProofUse {
            thumbprint: KeyThumbprint::parse("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
                .expect("RFC jkt"),
            jti: "-BwC3ESc6acc2lTc".to_owned(),
            expires_at: Timestamp::from_unix_secs(RFC_IAT + 60),
        })
    );
    assert!(check(&signed(&header(), &claims(""))).is_ok());
}

#[test]
fn the_target_is_compared_normalised_and_without_query_or_fragment() {
    let at = Timestamp::from_unix_secs(RFC_IAT);
    for target in [
        "https://SERVER.example.com/token",
        "https://server.example.com:443/token",
        "https://server.example.com/token?x=1#frag",
    ] {
        assert!(
            verify_proof(RFC_PROOF, "POST", target, at).is_ok(),
            "{target}"
        );
    }
    for target in [
        "https://server.example.com/token2",
        "https://other.example.com/token",
        "http://server.example.com/token",
        "https://server.example.com:8443/token",
        "not a uri",
    ] {
        assert_eq!(
            verify_proof(RFC_PROOF, "POST", target, at),
            refused(Reason::DpopClaims),
            "{target}"
        );
    }
    assert_eq!(
        verify_proof(RFC_PROOF, "GET", RFC_TARGET, at),
        refused(Reason::DpopClaims)
    );
}

#[test]
fn a_proof_is_fresh_for_a_minute_and_may_lead_the_clock_by_seconds() {
    for now in [RFC_IAT - 5, RFC_IAT, RFC_IAT + 60] {
        assert!(
            verify_proof(
                RFC_PROOF,
                "POST",
                RFC_TARGET,
                Timestamp::from_unix_secs(now)
            )
            .is_ok(),
            "{now}"
        );
    }
    for now in [RFC_IAT - 6, RFC_IAT + 61] {
        assert_eq!(
            verify_proof(
                RFC_PROOF,
                "POST",
                RFC_TARGET,
                Timestamp::from_unix_secs(now)
            ),
            refused(Reason::DpopTime),
            "{now}"
        );
    }
}

#[test]
fn the_header_must_type_the_proof_and_carry_its_own_public_key() {
    let jwk = ed_jwk();
    for header in [
        format!(r#"{{"typ":"jwt","alg":"EdDSA","jwk":{jwk}}}"#),
        format!(r#"{{"alg":"EdDSA","jwk":{jwk}}}"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"HS256","jwk":{jwk}}}"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"none","jwk":{jwk}}}"#),
        r#"{"typ":"dpop+jwt","alg":"EdDSA"}"#.to_owned(),
        format!(
            r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{}}}"#,
            jwk.replace('}', &format!(r#","d":"{SEED}"}}"#))
        ),
        format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{OTHER_JWK}}}"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{jwk},"crit":["x"],"x":1}}"#),
    ] {
        assert_eq!(
            check(&signed(&header, &claims(""))),
            refused(Reason::DpopProof),
            "{header}"
        );
    }
}

#[test]
fn a_jti_is_required_and_bounded() {
    for body in [
        claims("").replace(r#""jti":"p-1","#, ""),
        claims("").replace(r#""jti":"p-1""#, r#""jti":"""#),
        claims("").replace("p-1", &"j".repeat(257)),
    ] {
        assert_eq!(
            check(&signed(&header(), &body)),
            refused(Reason::DpopClaims),
            "{body}"
        );
    }
}

/// RFC 9449 §7.1: an access token and the `ath` its proofs carry.
const RFC_ACCESS_TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
const RFC_ATH: &str = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo";

fn at_resource(proof: &str) -> Result<ProofUse, Refusal> {
    verify_resource_proof(
        proof,
        "POST",
        "https://id.example.com/acme/token",
        RFC_ACCESS_TOKEN,
        Timestamp::from_unix_secs(NOW),
    )
}

#[test]
fn a_proof_at_a_resource_carries_the_hash_of_the_token_it_accompanies() {
    let used = at_resource(&signed(
        &header(),
        &claims(&format!(r#","ath":"{RFC_ATH}""#)),
    ))
    .expect("the RFC hash of the RFC token");
    assert_eq!(used.jti, "p-1");
    for extra in [
        String::new(),
        r#","ath":"""#.to_owned(),
        r#","ath":"fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEp""#.to_owned(),
        format!(r#","ath":"{RFC_ATH}=""#),
    ] {
        assert_eq!(
            at_resource(&signed(&header(), &claims(&extra))),
            refused(Reason::DpopClaims),
            "{extra}"
        );
    }
}
