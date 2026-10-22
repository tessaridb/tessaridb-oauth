//! Request limits on the public routes, counted in the store per client address before any route runs.
//!
//! The client is the connection's peer address: an IPv4 address whole, an IPv6 address by its /64, which one
//! subscriber is commonly given whole and could otherwise spend as many limits as it has addresses. A forwarded
//! header is not read, because the client writes it unless a trusted proxy overwrites it. A request that arrives with
//! no peer address — never on the listener, which always records one — is counted under one shared name rather than
//! not at all. Counting needs the store, and a store that does not answer refuses the request. Every counted answer,
//! served or refused, says the limit, what is left of it and the group it belongs to, so a client can slow down
//! before it is refused.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tessari_oauth_storage::throttle::{Admission, Limit};

use crate::state::PublicState;
use crate::{Error, Result};

/// The route group of the metadata and key-set reads.
const READ_GROUP: &str = "read";

/// The route group of the token requests.
const TOKEN_GROUP: &str = "token";

/// The route group of the authorization requests.
const AUTHORIZE_GROUP: &str = "authorize";

/// The route group of the sign-in steps.
const LOGIN_GROUP: &str = "login";

/// The route group of the account portal's requests.
const ACCOUNT_GROUP: &str = "account";

/// The counted name of a request with no peer address.
const NO_ADDRESS: &str = "no-address";

/// The name a request's client was counted under, left on the request for a route that counts more by it.
#[derive(Clone)]
pub(crate) struct ClientAddress(pub(crate) String);

/// The name a client is counted under.
fn client(request: &Request) -> String {
    let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() else {
        tracing::warn!(
            uri = %request.uri(),
            "a request without a peer address is counted under a shared name"
        );
        return NO_ADDRESS.to_owned();
    };
    match peer.ip() {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => mapped.to_string(),
            None => {
                let [a, b, c, d, ..] = address.segments();
                format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
            }
        },
    }
}

/// Count the request under the read limit, and refuse it past the limit or when the store cannot count.
pub(crate) async fn reads(
    State(state): State<PublicState>,
    request: Request,
    next: Next,
) -> Result<Response> {
    let limit = state.read_limit;
    count(&state, READ_GROUP, limit, request, next).await
}

/// Count the request under the token limit, and refuse it past the limit or when the store cannot count.
pub(crate) async fn tokens(
    State(state): State<PublicState>,
    request: Request,
    next: Next,
) -> Result<Response> {
    let limit = state.token_limit;
    count(&state, TOKEN_GROUP, limit, request, next).await
}

/// Count the request under the authorization limit, and refuse it past the limit or when the store cannot count.
pub(crate) async fn authorizations(
    State(state): State<PublicState>,
    request: Request,
    next: Next,
) -> Result<Response> {
    let limit = state.authorize_limit;
    count(&state, AUTHORIZE_GROUP, limit, request, next).await
}

/// Count the request under the sign-in limit, and refuse it past the limit or when the store cannot count.
pub(crate) async fn logins(
    State(state): State<PublicState>,
    request: Request,
    next: Next,
) -> Result<Response> {
    let limit = state.login_limit;
    count(&state, LOGIN_GROUP, limit, request, next).await
}

/// Count the request under the sign-in limit's numbers in a count of its own, and refuse it past the limit or when
/// the store cannot count.
pub(crate) async fn accounts(
    State(state): State<PublicState>,
    request: Request,
    next: Next,
) -> Result<Response> {
    let limit = state.login_limit;
    count(&state, ACCOUNT_GROUP, limit, request, next).await
}

/// Count the request in `group` under `limit`, then serve or refuse it.
async fn count(
    state: &PublicState,
    group: &'static str,
    limit: Limit,
    mut request: Request,
    next: Next,
) -> Result<Response> {
    let client = client(&request);
    request
        .extensions_mut()
        .insert(ClientAddress(client.clone()));
    let admission = state
        .throttle
        .admit(group, &client, limit, (state.clock)())
        .await
        .map_err(Error::Store)?;
    let (mut response, remaining) = match admission {
        Admission::Admitted { remaining } => (next.run(request).await, remaining),
        Admission::Refused { retry_after_secs } => {
            tracing::warn!(group, %client, "a client passed its request limit");
            (Error::Throttled { retry_after_secs }.into_response(), 0)
        }
    };
    let headers = response.headers_mut();
    for (name, value) in [
        ("x-ratelimit-limit", limit.requests.get()),
        ("x-ratelimit-remaining", remaining),
    ] {
        headers.insert(HeaderName::from_static(name), HeaderValue::from(value));
    }
    headers.insert(
        HeaderName::from_static("x-ratelimit-class"),
        HeaderValue::from_static(group),
    );
    Ok(response)
}
