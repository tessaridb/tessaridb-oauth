//! Client credentials for the token endpoint's tests: a client assertion, a DPoP key that makes proofs, and the
//! claims of an issued access token read back.

use axum::body::Body;
use axum::http::Request;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tessari_oauth_api::public_router;
use tessari_oauth_infrastructure::custody::SigningKey;
use tessari_oauth_types::{KeyThumbprint, base64url};
use tower::ServiceExt;

use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, Server, issuer, plenty, state};

pub(crate) const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A client's DPoP key: an Ed25519 pair from a fixed seed.
pub(crate) struct Holder {
    pair: Ed25519KeyPair,
}

impl Holder {
    pub(crate) fn new(seed: u8) -> Self {
        Self {
            pair: Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("a seed is a key"),
        }
    }

    pub(crate) fn thumbprint(&self) -> String {
        KeyThumbprint::of_ed25519(self.pair.public_key().as_ref())
            .as_str()
            .to_owned()
    }

    /// A proof for `htm` `htu` identified by `jti`, made now.
    pub(crate) fn proof(&self, jti: &str, htm: &str, htu: &str) -> String {
        let header = format!(
            r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}"}}}}"#,
            base64url::encode(self.pair.public_key().as_ref())
        );
        let claims = format!(r#"{{"jti":"{jti}","htm":"{htm}","htu":"{htu}","iat":{NOW}}}"#);
        let input = format!(
            "{}.{}",
            base64url::encode(header.as_bytes()),
            base64url::encode(claims.as_bytes())
        );
        format!(
            "{input}.{}",
            base64url::encode(self.pair.sign(input.as_bytes()).as_ref())
        )
    }

    /// A proof for this tenant's token endpoint.
    pub(crate) fn at_token(&self, jti: &str) -> String {
        self.proof(jti, "POST", &target())
    }
}

/// `acme`'s token endpoint, as a proof names it.
pub(crate) fn target() -> String {
    format!("{}/oauth2/token", issuer("acme"))
}

/// POST `pairs` to `acme`'s token endpoint with one `DPoP` header per proof.
pub(crate) async fn post_with(server: &Server, pairs: &[(&str, &str)], proofs: &[&str]) -> Answer {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut request = Request::post("/acme/oauth2/token")
        .header("content-type", "application/x-www-form-urlencoded");
    for proof in proofs {
        request = request.header("dpop", *proof);
    }
    let response = public_router(state(server, plenty()))
        .oneshot(request.body(Body::from(body)).expect("a request"))
        .await
        .expect("the router answers");
    answer(response).await
}

/// The payload of the access token in `answer`, read without verifying it (the code-grant tests verify).
pub(crate) fn payload(answer: &Answer) -> serde_json::Value {
    let compact = answer.body["access_token"]
        .as_str()
        .expect("an access token");
    let middle = compact.split('.').nth(1).expect("three segments");
    serde_json::from_slice(&base64url::decode(middle).expect("base64url")).expect("JSON")
}

/// An assertion by `client` addressed to `acme`'s issuer, identified by `jti`.
pub(crate) fn assertion(key: &SigningKey, client: &str, jti: &str) -> String {
    let claims = format!(
        r#"{{"iss":"{client}","sub":"{client}","aud":"{}","exp":{},"jti":"{jti}"}}"#,
        issuer("acme"),
        NOW + 60
    );
    key.sign_compact("JWT", claims.as_bytes()).expect("signed")
}
