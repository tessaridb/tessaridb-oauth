//! Provisioning a company registers its admin console as a client of the company's issuer: redirected back only to
//! the console's own callback, asking for nothing past `openid`, addressed to the console, and holding no grant an
//! outside caller could redeem at the token endpoint. Provisioning again changes nothing.

use tessari_oauth_constants::ADMIN_CONSOLE_CLIENT;
use tessari_oauth_core::clients::AuthMethod;
use tessari_oauth_types::{ClientId, TenantId, Timestamp};

use crate::fresh_on;

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn provisioning_registers_the_admin_console_once() {
    let storage = fresh_on(
        tessari_oauth_test_support::plain_node().expect("the plain node is named"),
        2,
    );
    let acme = TenantId::parse("acme").expect("a tenant id");
    for at in [1, 2] {
        storage
            .provision_company(
                &acme,
                "https://id.example.com",
                "https://admin.example.com",
                Timestamp::from_unix_secs(at),
            )
            .await
            .expect("provisioned");
    }
    let console = storage
        .clients
        .find(
            &acme,
            &ClientId::parse(ADMIN_CONSOLE_CLIENT).expect("a client id"),
        )
        .await
        .expect("an answer")
        .expect("the console is registered");
    let redirects: Vec<&str> = console
        .redirect_uris
        .iter()
        .map(|uri| uri.as_str())
        .collect();
    assert_eq!(redirects, ["https://admin.example.com/admin/acme/callback"]);
    let scopes: Vec<&str> = console.scope_ceiling.iter().collect();
    assert_eq!(scopes, ["openid"]);
    let resources: Vec<&str> = console
        .resources
        .iter()
        .map(|resource| resource.as_str())
        .collect();
    assert_eq!(resources, ["https://id.example.com/acme/admin"]);
    assert_eq!(console.auth_method, AuthMethod::None);
    assert!(
        console.grant_types.is_empty(),
        "nothing to redeem at /token"
    );
    assert!(console.post_logout_redirect_uris.is_empty());
    assert!(console.backchannel_logout_uri.is_none());
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_console_served_in_the_clear_on_loopback_is_registered() {
    let storage = fresh_on(
        tessari_oauth_test_support::plain_node().expect("the plain node is named"),
        2,
    );
    let acme = TenantId::parse("acme").expect("a tenant id");
    storage
        .provision_company(
            &acme,
            "https://id.example.com",
            "http://127.0.0.1:9443",
            Timestamp::from_unix_secs(1),
        )
        .await
        .expect("provisioned");
    let console = storage
        .clients
        .find(
            &acme,
            &ClientId::parse(ADMIN_CONSOLE_CLIENT).expect("a client id"),
        )
        .await
        .expect("an answer")
        .expect("the console is registered");
    let redirects: Vec<&str> = console
        .redirect_uris
        .iter()
        .map(|uri| uri.as_str())
        .collect();
    assert_eq!(redirects, ["http://127.0.0.1:9443/admin/acme/callback"]);
}
