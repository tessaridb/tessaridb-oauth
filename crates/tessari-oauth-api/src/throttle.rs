//! Request limits on the public routes, counted in the store per client address before any route runs.
//!
//! The client is the connection's peer address: an IPv4 address whole, an IPv6 address by its /64, which one
//! subscriber is commonly given whole and could otherwise spend as many limits as it has addresses. A forwarded
//! header is not read, because the client writes it unless a trusted proxy overwrites it. A request that arrives with
//! no peer address — never on the listener, which always records one — is counted under one shared name rather than
//! not at all. Counting needs the store, and a store that does not answer refuses the request.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use tessari_oauth_storage::throttle::Admission;

use crate::state::PublicState;
use crate::{Error, Result};

/// The route group of the metadata and key-set reads.
const READ_GROUP: &str = "read";

/// The counted name of a request with no peer address.
const NO_ADDRESS: &str = "no-address";

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
    let client = client(&request);
    let admission = state
        .throttle
        .admit(READ_GROUP, &client, state.read_limit, (state.clock)())
        .await
        .map_err(Error::Store)?;
    match admission {
        Admission::Admitted => Ok(next.run(request).await),
        Admission::Refused { retry_after_secs } => {
            tracing::warn!(group = READ_GROUP, %client, "a client passed its request limit");
            Err(Error::Throttled { retry_after_secs })
        }
    }
}
