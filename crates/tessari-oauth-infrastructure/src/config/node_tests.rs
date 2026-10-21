use std::collections::HashMap;

use super::NodeConfig;
use crate::Error;

const REQUIRED: [&str; 9] = [
    "TESSARIDB_OAUTH_PUBLIC_URL",
    "TESSARIDB_OAUTH_TLS_CERT",
    "TESSARIDB_OAUTH_TLS_KEY",
    "TESSARIDB_OAUTH_KEK",
    "TESSARIDB_OAUTH_STORE",
    "TESSARIDB_OAUTH_STORE_USER",
    "TESSARIDB_OAUTH_STORE_PASSWORD",
    "TESSARIDB_OAUTH_REGION",
    "TESSARIDB_OAUTH_TENANTS",
];

fn environment() -> HashMap<&'static str, String> {
    HashMap::from([
        (
            "TESSARIDB_OAUTH_PUBLIC_URL",
            "https://id.example.com".to_owned(),
        ),
        ("TESSARIDB_OAUTH_TLS_CERT", "/run/tls/cert.pem".to_owned()),
        ("TESSARIDB_OAUTH_TLS_KEY", "/run/tls/key.pem".to_owned()),
        ("TESSARIDB_OAUTH_KEK", "/run/secrets/kek".to_owned()),
        ("TESSARIDB_OAUTH_STORE", "127.0.0.1:7000".to_owned()),
        ("TESSARIDB_OAUTH_STORE_USER", "oauth".to_owned()),
        ("TESSARIDB_OAUTH_STORE_PASSWORD", "s3cret-value".to_owned()),
        ("TESSARIDB_OAUTH_REGION", "eu".to_owned()),
        ("TESSARIDB_OAUTH_TENANTS", "acme, globex".to_owned()),
    ])
}

fn read(environment: &HashMap<&'static str, String>) -> crate::Result<NodeConfig> {
    NodeConfig::from_lookup(|key| environment.get(key).cloned())
}

#[test]
fn a_complete_environment_is_read_with_the_documented_defaults() {
    let config = read(&environment()).expect("a valid environment");
    assert_eq!(config.public.url, "https://id.example.com");
    assert_eq!(config.public.address.to_string(), "0.0.0.0:8443");
    assert_eq!(config.public.tls_key.to_str(), Some("/run/tls/key.pem"));
    assert_eq!(config.store.address, "127.0.0.1:7000");
    assert_eq!(config.store.connections.get(), 16);
    assert!(config.store.authority.is_none());
    assert_eq!(config.region, "eu");
    let tenants: Vec<&str> = config
        .tenants
        .iter()
        .map(|tenant| tenant.as_str())
        .collect();
    assert_eq!(tenants, ["acme", "globex"]);
    assert_eq!(
        (
            config.read_limit.requests.get(),
            config.read_limit.window_secs.get()
        ),
        (300, 60)
    );
}

#[test]
fn every_required_variable_that_is_missing_is_named() {
    for key in REQUIRED {
        let mut environment = environment();
        environment.remove(key);
        let refused = read(&environment);
        assert!(
            matches!(&refused, Err(Error::Unset { key: named }) if *named == key),
            "{key}: {refused:?}"
        );
    }
}

#[test]
fn a_value_that_does_not_fit_is_refused_naming_its_variable_and_value() {
    for (key, value) in [
        ("TESSARIDB_OAUTH_PUBLIC_URL", "http://id.example.com"),
        ("TESSARIDB_OAUTH_PUBLIC_URL", "https://id.example.com/"),
        ("TESSARIDB_OAUTH_PUBLIC_URL", "https://id.example.com?x=1"),
        ("TESSARIDB_OAUTH_PUBLIC_URL", "https://user@id.example.com"),
        ("TESSARIDB_OAUTH_PUBLIC_ADDRESS", "localhost"),
        ("TESSARIDB_OAUTH_STORE_CONNECTIONS", "0"),
        ("TESSARIDB_OAUTH_READ_LIMIT", "0"),
        ("TESSARIDB_OAUTH_READ_LIMIT", "many"),
        ("TESSARIDB_OAUTH_READ_WINDOW_SECS", "-1"),
        ("TESSARIDB_OAUTH_TENANTS", "acme,,globex"),
        ("TESSARIDB_OAUTH_TENANTS", "acme,acme"),
        ("TESSARIDB_OAUTH_TENANTS", "Not A Tenant"),
    ] {
        let mut environment = environment();
        environment.insert(key, value.to_owned());
        let refused = read(&environment);
        assert!(
            matches!(&refused, Err(Error::Invalid { key: named, value: seen, .. })
                if *named == key && seen == value),
            "{key}={value}: {refused:?}"
        );
    }
}

#[test]
fn the_store_password_never_appears_in_debug_output() {
    let config = read(&environment()).expect("a valid environment");
    let printed = format!("{config:?}");
    assert!(!printed.contains("s3cret-value"), "{printed}");
    assert!(printed.contains("127.0.0.1:7000"), "{printed}");
}
