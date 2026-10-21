# TessariDB OAuth

An OAuth 2.1 authorization server and OpenID provider that keeps every piece of its state in
[TessariDB](https://docs.tessaridb.com/). One binary carries the protocol endpoints, the users' account
portal and an embedded admin panel on its own listener.

> Status: early development. The workspace and the first protocol value types exist; no endpoint is served yet.

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
authorization-request and code-redemption validators in their fixed check order.

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

## Licence

Business Source License 1.1 — see [LICENSE](LICENSE). Production use is permitted, including commercial use,
except providing the software to third parties as a hosted identity service or reselling it. Each version
converts to the Apache License 2.0 on its Change Date.
