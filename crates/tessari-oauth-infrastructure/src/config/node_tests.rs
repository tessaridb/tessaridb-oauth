use std::collections::HashMap;

use super::NodeConfig;
use crate::Error;
use crate::custody::PasswordCost;

const REQUIRED: [&str; 9] = [
    "TESSARIDB_OAUTH_PUBLIC_URL",
    "TESSARIDB_OAUTH_ADMIN_URL",
    "TESSARIDB_OAUTH_KEK",
    "TESSARIDB_OAUTH_STORE",
    "TESSARIDB_OAUTH_STORE_USER",
    "TESSARIDB_OAUTH_STORE_PASSWORD",
    "TESSARIDB_OAUTH_REGION",
    "TESSARIDB_OAUTH_TENANTS",
    "TESSARIDB_OAUTH_PEPPER",
];

fn environment() -> HashMap<&'static str, String> {
    HashMap::from([
        (
            "TESSARIDB_OAUTH_PUBLIC_URL",
            "https://id.example.com".to_owned(),
        ),
        (
            "TESSARIDB_OAUTH_ADMIN_URL",
            "https://admin.example.com".to_owned(),
        ),
        ("TESSARIDB_OAUTH_KEK", "/run/secrets/kek".to_owned()),
        ("TESSARIDB_OAUTH_STORE", "127.0.0.1:7000".to_owned()),
        ("TESSARIDB_OAUTH_STORE_USER", "oauth".to_owned()),
        ("TESSARIDB_OAUTH_STORE_PASSWORD", "s3cret-value".to_owned()),
        ("TESSARIDB_OAUTH_REGION", "eu".to_owned()),
        ("TESSARIDB_OAUTH_TENANTS", "acme, globex".to_owned()),
        ("TESSARIDB_OAUTH_PEPPER", "/run/secrets/pepper".to_owned()),
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
    assert_eq!(config.public.tls, None, "in the clear by default");
    assert!(
        config.public.trusted_proxies.is_empty(),
        "no proxy trusted by default"
    );
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
    assert_eq!(
        (
            config.token_limit.requests.get(),
            config.token_limit.window_secs.get()
        ),
        (60, 60)
    );
    assert_eq!(
        (
            config.authorize_limit.requests.get(),
            config.authorize_limit.window_secs.get()
        ),
        (120, 60)
    );
    assert_eq!(
        (
            config.login_limit.requests.get(),
            config.login_limit.window_secs.get()
        ),
        (30, 60)
    );
    assert_eq!(config.pepper.to_str(), Some("/run/secrets/pepper"));
    assert_eq!(
        config.password_cost,
        PasswordCost::new(65_536, 3, 1).expect("the floor")
    );
    assert_eq!(config.password_concurrency.get(), 4);
}

#[test]
fn a_password_cost_below_the_floor_is_refused_and_one_above_it_read() {
    let mut below = environment();
    below.insert("TESSARIDB_OAUTH_PASSWORD_ITERATIONS", "2".to_owned());
    assert!(matches!(
        read(&below),
        Err(Error::InvalidConfig {
            field: "password_hash_cost",
            ..
        })
    ));
    let mut above = environment();
    above.insert("TESSARIDB_OAUTH_PASSWORD_MEMORY_KIB", "131072".to_owned());
    assert_eq!(
        read(&above).expect("a valid environment").password_cost,
        PasswordCost::new(131_072, 3, 1).expect("a cost")
    );
    let mut lanes = environment();
    lanes.insert("TESSARIDB_OAUTH_PASSWORD_PARALLELISM", "2".to_owned());
    assert_eq!(
        read(&lanes).expect("a valid environment").password_cost,
        PasswordCost::new(65_536, 3, 2).expect("a cost")
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
        ("TESSARIDB_OAUTH_TOKEN_LIMIT", "0"),
        ("TESSARIDB_OAUTH_TOKEN_WINDOW_SECS", "many"),
        ("TESSARIDB_OAUTH_AUTHORIZE_LIMIT", "0"),
        ("TESSARIDB_OAUTH_AUTHORIZE_WINDOW_SECS", "-1"),
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

#[test]
fn the_admin_console_is_read_with_its_own_listener() {
    let config = read(&environment()).expect("a valid environment");
    assert_eq!(config.admin.url, "https://admin.example.com");
    assert_eq!(config.admin.address.to_string(), "0.0.0.0:9443");
    let mut moved = environment();
    moved.insert("TESSARIDB_OAUTH_ADMIN_ADDRESS", "127.0.0.1:9500".to_owned());
    assert_eq!(
        read(&moved)
            .expect("a valid environment")
            .admin
            .address
            .to_string(),
        "127.0.0.1:9500"
    );
}

#[test]
fn the_admin_console_needs_an_https_origin_apart_from_the_public_one() {
    for refused in [
        "https://id.example.com",
        "https://id.example.com/admin",
        "http://admin.example.com",
        "https://admin.example.com/",
        "https://admin.example.com?x=1",
    ] {
        let mut environment = environment();
        environment.insert("TESSARIDB_OAUTH_ADMIN_URL", refused.to_owned());
        assert!(
            matches!(
                read(&environment),
                Err(Error::Invalid {
                    key: "TESSARIDB_OAUTH_ADMIN_URL",
                    ..
                })
            ),
            "{refused} is refused"
        );
    }
}

#[test]
fn the_admin_console_serves_in_the_clear_until_given_a_certificate() {
    let plain = read(&environment()).expect("a valid environment");
    assert_eq!(plain.admin.tls, None);
    let mut secured = environment();
    secured.insert(
        "TESSARIDB_OAUTH_ADMIN_TLS_CERT",
        "/run/admin/cert.pem".to_owned(),
    );
    secured.insert(
        "TESSARIDB_OAUTH_ADMIN_TLS_KEY",
        "/run/admin/key.pem".to_owned(),
    );
    let tls = read(&secured)
        .expect("a valid environment")
        .admin
        .tls
        .expect("a certificate");
    assert_eq!(
        (tls.cert.to_str(), tls.key.to_str()),
        (Some("/run/admin/cert.pem"), Some("/run/admin/key.pem"))
    );
    for (given, missing) in [
        (
            "TESSARIDB_OAUTH_ADMIN_TLS_CERT",
            "TESSARIDB_OAUTH_ADMIN_TLS_KEY",
        ),
        (
            "TESSARIDB_OAUTH_ADMIN_TLS_KEY",
            "TESSARIDB_OAUTH_ADMIN_TLS_CERT",
        ),
    ] {
        let mut half = environment();
        half.insert(given, "/run/admin/file.pem".to_owned());
        assert!(
            matches!(read(&half), Err(Error::Unset { key }) if key == missing),
            "{given} alone names {missing}"
        );
    }
}

#[test]
fn a_console_in_the_clear_is_reached_only_on_a_loopback_address() {
    for accepted in ["http://127.0.0.1:9443", "http://[::1]:9443"] {
        let mut environment = environment();
        environment.insert("TESSARIDB_OAUTH_ADMIN_URL", accepted.to_owned());
        assert_eq!(
            read(&environment).expect("a valid environment").admin.url,
            accepted
        );
    }
    for refused in ["http://localhost:9443", "http://10.0.0.5:9443"] {
        let mut environment = environment();
        environment.insert("TESSARIDB_OAUTH_ADMIN_URL", refused.to_owned());
        assert!(
            matches!(
                read(&environment),
                Err(Error::Invalid {
                    key: "TESSARIDB_OAUTH_ADMIN_URL",
                    ..
                })
            ),
            "{refused} is refused"
        );
    }
}

#[test]
fn the_public_listener_serves_in_the_clear_until_given_a_certificate() {
    let mut secured = environment();
    secured.insert("TESSARIDB_OAUTH_TLS_CERT", "/run/tls/cert.pem".to_owned());
    secured.insert("TESSARIDB_OAUTH_TLS_KEY", "/run/tls/key.pem".to_owned());
    let tls = read(&secured)
        .expect("a valid environment")
        .public
        .tls
        .expect("a certificate");
    assert_eq!(
        (tls.cert.to_str(), tls.key.to_str()),
        (Some("/run/tls/cert.pem"), Some("/run/tls/key.pem"))
    );
    for (given, missing) in [
        ("TESSARIDB_OAUTH_TLS_CERT", "TESSARIDB_OAUTH_TLS_KEY"),
        ("TESSARIDB_OAUTH_TLS_KEY", "TESSARIDB_OAUTH_TLS_CERT"),
    ] {
        let mut half = environment();
        half.insert(given, "/run/tls/file.pem".to_owned());
        assert!(
            matches!(read(&half), Err(Error::Unset { key }) if key == missing),
            "{given} alone names {missing}"
        );
    }
}

#[test]
fn trusted_proxies_are_read_and_a_list_that_does_not_parse_is_refused_by_name() {
    let mut proxied = environment();
    proxied.insert(
        "TESSARIDB_OAUTH_TRUSTED_PROXIES",
        "10.0.0.0/8, ::1".to_owned(),
    );
    let config = read(&proxied).expect("a valid environment");
    assert!(
        config
            .public
            .trusted_proxies
            .contains("10.1.2.3".parse().expect("an address"))
    );
    assert!(
        !config
            .public
            .trusted_proxies
            .contains("192.0.2.1".parse().expect("an address"))
    );
    proxied.insert("TESSARIDB_OAUTH_TRUSTED_PROXIES", "nginx".to_owned());
    assert!(
        matches!(
            read(&proxied),
            Err(Error::Invalid {
                key: "TESSARIDB_OAUTH_TRUSTED_PROXIES",
                ..
            })
        ),
        "a name is not an address"
    );
}

#[test]
fn mail_is_off_until_a_relay_is_named_and_then_read_from_the_smtp_variables() {
    assert_eq!(
        read(&environment()).expect("a valid environment").mail,
        None
    );
    let mut mailing = environment();
    mailing.insert(
        "TESSARIDB_OAUTH_SMTP_URL",
        "smtps://mail.example.com".to_owned(),
    );
    mailing.insert(
        "TESSARIDB_OAUTH_SMTP_FROM",
        "no-reply@id.example.com".to_owned(),
    );
    let mail = read(&mailing)
        .expect("a valid environment")
        .mail
        .expect("a relay");
    assert_eq!((mail.host.as_str(), mail.port), ("mail.example.com", 465));
    mailing.remove("TESSARIDB_OAUTH_SMTP_URL");
    assert!(matches!(
        read(&mailing),
        Err(Error::Unset {
            key: "TESSARIDB_OAUTH_SMTP_URL"
        })
    ));
}
