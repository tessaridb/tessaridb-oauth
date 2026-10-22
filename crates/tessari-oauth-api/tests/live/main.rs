//! The public routes end to end over a real TessariDB node, called through the router as the listener calls it.
//!
//! Needs `TESSARIDB_OAUTH_TEST_STORE`, `TESSARIDB_OAUTH_TEST_USER` and `TESSARIDB_OAUTH_TEST_PASSWORD`; without them
//! the store-backed tests are `ignored`, and `cargo test -p tessari-oauth-api --test live -- --ignored` runs them.

#![cfg(test)]

mod authorize;
mod login;
mod login_factors;
mod login_factors_race;
mod login_password;
mod par;
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
mod userinfo;
