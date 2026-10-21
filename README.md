# TessariDB OAuth

An OAuth 2.1 authorization server and OpenID provider that keeps every piece of its state in
[TessariDB](https://docs.tessaridb.com/). One binary carries the protocol endpoints, the users' account
portal and an embedded admin panel on its own listener.

> Status: early development. The protocol value types, the request validators and single-use code storage on
> TessariDB exist; no endpoint is served yet.

## What it is for

- Sign-in and single sign-on for your own applications, with one issuer per tenant.
- Users manage their own profile, sessions, connected applications and security settings in the account portal.
- Administrators manage tenants, users, clients and keys from the admin panel, with every action recorded.
- Each tenant's identity data lives in one home region; requests for it elsewhere are redirected, never proxied.

## Standards

The design follows OAuth 2.1: authorization code with PKCE `S256` (RFC 7636) as the only browser flow, redirect
URIs matched exactly with only the native-app loopback port exception (RFC 8252 §7.3), and DPoP (RFC 9449) for
sender-constrained tokens, with keys named by their JWK thumbprint (RFC 7638). Implicit, hybrid token-returning and
password grants will not be offered. Implemented so far, as pure functions without a server: the PKCE `S256`
check, the redirect-URI type and its matching rule, the thumbprint, tenant, client and scope value types, and the
authorization-request and code-redemption validators in their fixed check order. Authorization codes are stored
by their SHA-256 digest only, and are spent with one conditional write, so of any number of simultaneous
redemptions exactly one succeeds and the rest are reported as replays.

## Layout

| Crate | Role |
|---|---|
| `tessari-oauth-constants` | every limit and alphabet, with its unit and source |
| `tessari-oauth-types` | protocol values as types, and the error taxonomy |
| `tessari-oauth-core` | the protocol core, pure and testable without a server |
| `tessari-oauth-storage` | persistence on TessariDB, by domain |
| `tessari-oauth-infrastructure` | database connection, key custody, guarded outbound HTTP |
| `tessari-oauth-observability` | tracing and metrics, with secrets kept out of logs |
| `tessari-oauth-api` | protocol, account and admin routes |
| `tessari-oauth-daemons` | expiry, key rotation, logout delivery |
| `tessari-oauth-node` | the `tessaridb-oauth` binary |

## Building and checking

Requires the stable Rust toolchain (`rust-version` 1.98).

```sh
cargo build
cargo t          # every library and integration test
cargo lint       # clippy over all targets with warnings denied
cargo fmt --all --check
cargo deny check # licences, advisories, sources
```

The storage tests that need a database are marked `ignored` and run against a TessariDB node you name:

```sh
docker run -d --rm --name oauth-live -p 127.0.0.1:39601:9080 \
  -e TESSARIDB_INITIAL_USER=oauth -e TESSARIDB_INITIAL_PASSWORD="$PASSWORD" tessaridb/tessaridb:0.36.2
TESSARIDB_OAUTH_TEST_STORE=127.0.0.1:39601 TESSARIDB_OAUTH_TEST_USER=oauth \
  TESSARIDB_OAUTH_TEST_PASSWORD="$PASSWORD" cargo test -p tessari-oauth-storage --test live -- --ignored
```

Each test works in a namespace of its own, so the suite can run repeatedly against one node.

## Licence

Business Source License 1.1 — see [LICENSE](LICENSE). Production use is permitted, including commercial use,
except providing the software to third parties as a hosted identity service or reselling it. Each version
converts to the Apache License 2.0 on its Change Date.
