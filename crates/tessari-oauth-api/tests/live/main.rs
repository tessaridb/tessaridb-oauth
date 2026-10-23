//! The public routes end to end over a real TessariDB node, called through the router as the listener calls it.
//!
//! Needs `TESSARIDB_OAUTH_TEST_STORE`, `TESSARIDB_OAUTH_TEST_USER` and `TESSARIDB_OAUTH_TEST_PASSWORD`; without them
//! the store-backed tests are `ignored`, and `cargo test -p tessari-oauth-api --test live -- --ignored` runs them.

#![cfg(test)]

mod account_app_removal;
mod account_email;
mod account_factors;
mod account_grants;
mod account_me;
mod account_notices;
mod account_password;
mod account_profile;
mod account_sessions;
mod account_verify;
mod admin_audit;
mod admin_branding;
mod admin_callback;
mod admin_clients;
mod admin_companies;
mod admin_groups;
mod admin_keys;
mod admin_mail;
mod admin_matrix;
mod admin_operators;
mod admin_pages;
mod admin_policy;
mod admin_session;
mod admin_signin;
mod admin_users;
mod admin_users_create;
mod admin_users_read;
mod authenticator;
mod authorize;
mod authorize_prompt;
mod authorize_resume;
mod browser_binding;
mod id_token;
mod login;
mod login_complete;
mod login_consent;
mod login_enroll;
mod login_factors;
mod login_factors_race;
mod login_passkey;
mod login_passkey_assertion;
mod login_passkey_counts;
mod login_password;
mod login_register;
mod login_reset;
mod logout;
mod pages;
mod par;
mod regions;
mod routes;
mod throttle;
mod token;
mod token_audit;
mod token_auth;
mod token_client_credentials;
mod token_clients;
mod token_dpop;
mod token_fixture;
mod token_refresh;
mod token_refusals;
mod token_revoke;
mod two_factor_policy;
mod userinfo;
