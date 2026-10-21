use super::RedirectUri;
use crate::Error;

fn registered(raw: &str) -> RedirectUri {
    RedirectUri::parse(raw).unwrap_or_else(|error| panic!("{raw} should register: {error}"))
}

fn refused(raw: &str) -> bool {
    matches!(
        RedirectUri::parse(raw),
        Err(Error::Invalid {
            field: "redirect_uri",
            ..
        })
    )
}

#[test]
fn https_private_use_and_loopback_uris_register_as_written() {
    for raw in [
        "https://app.example.com/callback",
        "https://app.example.com/callback?tenant=acme",
        "https://app.example.com:8443/cb",
        "com.example.app:/oauth2redirect",
        "http://127.0.0.1/callback",
        "http://127.0.0.1:8400/callback",
        "http://[::1]/callback",
    ] {
        assert_eq!(registered(raw).as_str(), raw);
    }
}

#[test]
fn a_registered_uri_matches_only_its_own_string() {
    let uri = registered("https://app.example.com/callback");
    assert!(uri.matches("https://app.example.com/callback"));
    for presented in [
        "https://app.example.com/callback/",
        "https://app.example.com/callback/evil",
        "https://app.example.com/Callback",
        "https://app.example.com/callback?x=1",
        "https://app.example.com/callback#x",
        "https://evil.app.example.com/callback",
        "https://app.example.com:443/callback",
        "http://app.example.com/callback",
        "https://app.example.com/callback%2f..",
    ] {
        assert!(!uri.matches(presented), "{presented} must not match");
    }
}

#[test]
fn uris_that_could_only_match_after_normalisation_are_refused() {
    for raw in [
        "https://App.Example.com/callback",
        "https://app.example.com:443/callback",
        "https://app.example.com",
        "HTTPS://app.example.com/callback",
        "https://app.example.com/a/../callback",
    ] {
        assert!(refused(raw), "{raw} is not in normalised form");
    }
}

#[test]
fn fragments_user_information_and_relative_references_are_refused() {
    for raw in [
        "https://app.example.com/callback#fragment",
        "https://user@app.example.com/callback",
        "https://user:secret@app.example.com/callback",
        "/callback",
        "",
        "not a uri",
    ] {
        assert!(refused(raw), "{raw} must be refused");
    }
}

#[test]
fn http_is_refused_except_on_a_loopback_ip_literal() {
    for raw in [
        "http://app.example.com/callback",
        "http://localhost/callback",
        "http://localhost:8400/callback",
        "http://10.0.0.1/callback",
    ] {
        assert!(refused(raw), "{raw} must be refused");
    }
}

#[test]
fn schemes_that_are_not_https_http_or_private_use_are_refused() {
    for raw in [
        "javascript:alert(1)",
        "data:text/html,hi",
        "file:///etc/passwd",
        "myapp:/cb",
    ] {
        assert!(refused(raw), "{raw} must be refused");
    }
}

#[test]
fn a_loopback_uri_matches_any_port_and_nothing_else() {
    let uri = registered("http://127.0.0.1/callback");
    for presented in [
        "http://127.0.0.1/callback",
        "http://127.0.0.1:51004/callback",
    ] {
        assert!(uri.matches(presented), "{presented} should match");
    }
    for presented in [
        "http://127.0.0.1:51004/other",
        "http://127.0.0.1:51004/callback?x=1",
        "http://127.0.0.1:51004/callback#x",
        "http://[::1]:51004/callback",
        "http://localhost:51004/callback",
        "https://127.0.0.1:51004/callback",
        "http://user@127.0.0.1:51004/callback",
        "http://127.0.0.2:51004/callback",
    ] {
        assert!(!uri.matches(presented), "{presented} must not match");
    }
}

#[test]
fn a_loopback_uri_registered_with_a_port_still_tolerates_another_port() {
    let uri = registered("http://[::1]:8400/callback");
    assert!(uri.matches("http://[::1]:61000/callback"));
    assert!(!uri.matches("http://127.0.0.1:8400/callback"));
}
