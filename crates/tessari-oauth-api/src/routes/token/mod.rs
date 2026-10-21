//! `POST /{tenant}/oauth2/token` (RFC 6749 §3.2), redeeming an authorization code (§4.1.3), a refresh token (§6) or
//! a confidential client's own credentials (§4.4).
//!
//! The checks run in a fixed order. The client is authenticated before the code is read, so a code never names its
//! presenter. The code is spent atomically before its bindings are checked, so it redeems once whatever the outcome,
//! and a code presented again revokes the refresh family it started. That family is started before the access token
//! is signed, so a redemption that loses to a replay signs nothing. A DPoP proof is verified once the client is
//! authenticated and spent only after every other check has passed. A refusal answers with the specification's
//! `error` code alone and records its precise reason in the audit log — identifiers only, never the code, the
//! verifier or the assertion.

mod answer;
mod client;
mod proof;
mod redeem;
mod refresh;

use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use tessari_oauth_core::clients::{ClientDirectory, ClientRegistration, GrantType};
use tessari_oauth_core::token::{self, Endpoint, PresentedAuth, Refusal};
use tessari_oauth_core::{Params, Reason};
use tessari_oauth_storage::replay::Spent;
use tessari_oauth_types::{ClientId, ErrorCode, TenantId};

use crate::Error;
use crate::state::PublicState;
use answer::{Issued, answer_refusal, no_store};
use redeem::redeem;

/// Why a request was not answered with tokens: refused by a check, or not served because the server failed.
enum Failure {
    Refused(Refusal),
    Server(Error),
}

impl From<Refusal> for Failure {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Server(error)
    }
}

const fn refusal(error: ErrorCode, reason: Reason) -> Refusal {
    Refusal { error, reason }
}

/// The one registration looked up for this request, as the directory the core authenticates against.
struct Found(Option<ClientRegistration>);

impl ClientDirectory for Found {
    fn find(&self, tenant: &TenantId, client_id: &ClientId) -> Option<ClientRegistration> {
        self.0
            .clone()
            .filter(|found| found.tenant == *tenant && found.client_id == *client_id)
    }
}

pub(super) async fn token(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> crate::Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let endpoint = Endpoint {
        tenant,
        issuer: issuer.to_owned(),
        now: (state.clock)(),
    };
    // A body that is not a form, or is larger than the endpoint reads, is refused before anything in it is read.
    let params = match form {
        Ok(Form(pairs)) => token::read(pairs),
        Err(_) => Err(refusal(ErrorCode::InvalidRequest, Reason::BodyNotForm)),
    };
    let client_id = params
        .as_ref()
        .ok()
        .and_then(|params| params.get("client_id"))
        .and_then(|raw| ClientId::parse(raw).ok());
    let outcome = match params {
        Ok(params) => exchange(&state, &endpoint, &headers, &params, client_id.as_ref()).await,
        Err(refused) => Err(Failure::Refused(refused)),
    };
    match outcome {
        Ok(issued) => Ok(no_store(Json(issued).into_response())),
        Err(Failure::Server(error)) => Err(error),
        Err(Failure::Refused(refused)) => {
            tracing::warn!(
                event = "token_refused",
                tenant = endpoint.tenant.as_str(),
                client = client_id.as_ref().map(ClientId::as_str),
                reason = ?refused.reason,
                error = refused.error.as_str(),
                "a token request was refused"
            );
            Ok(answer_refusal(refused, presents_basic(&headers)))
        }
    }
}

/// Authenticate the client, then redeem the grant it asks for.
async fn exchange(
    state: &PublicState,
    endpoint: &Endpoint,
    headers: &HeaderMap,
    params: &Params,
    client_id: Option<&ClientId>,
) -> Result<Issued, Failure> {
    let presented = presented(headers, params)?;
    let found = match client_id {
        Some(client_id) => state
            .clients
            .find(&endpoint.tenant, client_id)
            .await
            .map_err(Error::Store)?,
        None => None,
    };
    let authenticated = token::authenticate_client(endpoint, &Found(found), presented, params)?;
    if let Some(assertion) = &authenticated.assertion {
        let spent = state
            .replay
            .spend_assertion(&endpoint.tenant, assertion, endpoint.now)
            .await
            .map_err(Error::Store)?;
        if spent == Spent::Replayed {
            return Err(refusal(ErrorCode::InvalidClient, Reason::AssertionReplayed).into());
        }
    }
    let client = authenticated.client;
    let proof = proof::read(headers, endpoint, &client)?;
    match token::require_grant(params, &client)? {
        GrantType::AuthorizationCode => {
            redeem(state, endpoint, &client, params, proof.as_ref()).await
        }
        GrantType::RefreshToken => {
            refresh::refresh(state, endpoint, &client, params, proof.as_ref()).await
        }
        GrantType::ClientCredentials => {
            client::client_credentials(state, endpoint, &client, params, proof.as_ref()).await
        }
    }
}

/// The one client authentication method the request presents (RFC 6749 §2.3: never more than one).
fn presented(headers: &HeaderMap, params: &Params) -> Result<PresentedAuth, Refusal> {
    let mut methods = [
        (presents_basic(headers), PresentedAuth::ClientSecretBasic),
        (
            params.get("client_secret").is_some(),
            PresentedAuth::ClientSecretPost,
        ),
        (
            params.get("client_assertion").is_some(),
            PresentedAuth::PrivateKeyJwt,
        ),
    ]
    .into_iter()
    .filter_map(|(present, method)| present.then_some(method));
    match (methods.next(), methods.next()) {
        (None, _) => Ok(PresentedAuth::None),
        (Some(method), None) => Ok(method),
        (Some(_), Some(_)) => Err(refusal(
            ErrorCode::InvalidRequest,
            Reason::SeveralAuthMethods,
        )),
    }
}

/// Whether the request carries HTTP Basic credentials.
fn presents_basic(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.get(..6))
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("basic "))
}
