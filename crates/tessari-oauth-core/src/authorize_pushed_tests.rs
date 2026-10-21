//! `request_uri` (RFC 9126 §4): the pushed request it names is the request, so what is read here is only which
//! client asks for which pushed request — and anything malformed is refused at the server.

use tessari_oauth_types::ClientId;

use super::{Refusal, pushed};
use crate::Reason;

fn reason(pairs: &[(&str, &str)]) -> Reason {
    match pushed(pairs.iter().copied()) {
        Err(Refusal::RenderAtServer { reason, .. }) => reason,
        other => panic!("expected a refusal rendered at the server, got {other:?}"),
    }
}

#[test]
fn a_request_uri_names_the_client_and_the_pushed_id() {
    let named = pushed([
        ("client_id", "app"),
        ("request_uri", "urn:ietf:params:oauth:request_uri:abc123"),
        ("scope", "ignored"),
    ])
    .expect("well-formed");
    assert_eq!(
        named,
        Some((
            ClientId::parse("app").expect("a client id"),
            "abc123".to_owned()
        ))
    );
    assert_eq!(
        pushed([("client_id", "app")]).expect("no request_uri"),
        None
    );
}

#[test]
fn a_malformed_request_uri_is_refused_at_the_server() {
    let uri = "urn:ietf:params:oauth:request_uri:abc123";
    assert_eq!(reason(&[("request_uri", uri)]), Reason::MissingParameter);
    assert_eq!(
        reason(&[("client_id", "line\nbreak"), ("request_uri", uri)]),
        Reason::MalformedParameter
    );
    for other in [
        "https://client.example.com/request.jwt",
        "urn:ietf:params:oauth:request_uri:",
        "abc123",
    ] {
        assert_eq!(
            reason(&[("client_id", "app"), ("request_uri", other)]),
            Reason::RequestUriUnknown,
            "{other}"
        );
    }
    assert_eq!(
        reason(&[
            ("client_id", "app"),
            ("request_uri", uri),
            ("request_uri", uri)
        ]),
        Reason::DuplicateParameter
    );
}
