use super::Params;

#[test]
fn each_parameter_is_read_once() {
    let params = Params::from_pairs([("client_id", "app"), ("state", "xyz")]).expect("no repeats");
    assert_eq!(params.get("client_id"), Some("app"));
    assert_eq!(params.get("state"), Some("xyz"));
    assert_eq!(params.get("scope"), None);
}

#[test]
fn a_repeated_parameter_is_named_and_nothing_is_read() {
    let repeated = Params::from_pairs([
        ("redirect_uri", "https://app.example.com/cb"),
        ("client_id", "app"),
        ("redirect_uri", "https://evil.example/cb"),
    ]);
    assert_eq!(repeated, Err("redirect_uri".to_owned()));
}
