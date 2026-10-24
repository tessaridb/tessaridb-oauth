use super::StoreConfig;

#[test]
fn debug_formatting_never_shows_the_password() {
    let config = StoreConfig {
        address: "127.0.0.1:9080".to_owned(),
        user: "oauth".to_owned(),
        password: "correct horse battery".to_owned(),
        authority: None,
    };
    let printed = format!("{config:?}");
    assert!(printed.contains("127.0.0.1:9080"), "{printed}");
    assert!(!printed.contains("correct horse battery"), "{printed}");
}
