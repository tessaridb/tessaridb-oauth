# TessariDB OAuth

An OAuth 2.1 authorization server and OpenID provider that keeps every piece of its state in
[TessariDB](https://docs.tessaridb.com/). One binary carries the protocol endpoints, the users' account
portal and an embedded admin panel on its own listener.

> Status: early development. The binary serves each tenant's server metadata (RFC 8414) and key set (RFC 7517)
> over TLS and rotates the tenants' signing keys; the authorization, token and account endpoints are not served yet.

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
authorization-request, code-redemption and refresh-request validators in their fixed check order; a client
redeems only the grant types it registered, and a refresh may narrow its scopes but never widen them. Confidential clients authenticate with `private_key_jwt`: an Ed25519 or ES256 assertion
signed by a key the client registered, addressed to the tenant's issuer alone, and valid for at most five minutes. Each assertion is accepted once: its `jti` is recorded in a
TessariDB space until it could no longer be accepted, and a second presentation is refused as a replay. DPoP proofs
(RFC 9449) are checked the same way: typed `dpop+jwt`, signed by the public key they carry under the server's
algorithms, bound to this method and URI, at most a minute old, and accepted once per key; the token they accompany
is bound to that key's RFC 7638 thumbprint. Authorization codes are stored
by their SHA-256 digest only, and are spent with one conditional write, so of any number of simultaneous
redemptions exactly one succeeds and the rest are reported as replays. Consent is a record per user and client
holding the granted scopes, resources and consent policy version; a request outside it is answered with exactly
what must be asked, simultaneous grants are all kept, and a revocation records who made it. Refresh tokens rotate on every use and are kept as digests only; a token
presented again after it was rotated revokes its whole family, and a token lives at most 14 days unused and 30 days
in all.

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

## Running

The server reads its configuration from the environment when it starts, checks all of it, and refuses to start —
naming the variable — when anything is missing or does not fit. A `.env` file in the working directory is read
first, for development only.

| Variable (`TESSARIDB_OAUTH_…`) | Meaning | Default |
|---|---|---|
| `PUBLIC_URL` | the https base URL; tenant `acme`'s issuer is `<PUBLIC_URL>/acme` | required |
| `PUBLIC_ADDRESS` | where the public listener binds | `0.0.0.0:8443` |
| `TLS_CERT`, `TLS_KEY` | the listener's certificate chain and private key, PEM | required |
| `KEK` | the 32-byte key-encryption key file, mode 600 or 400; signing keys are stored sealed under it | required |
| `STORE`, `STORE_USER`, `STORE_PASSWORD` | the TessariDB node's wire address and the account the server signs in with | required |
| `STORE_AUTHORITY` | the PEM the node's certificate must lead to; without it only a loopback store is reached | none |
| `STORE_CONNECTIONS` | connections to the store at most | `16` |
| `REGION` | the region whose tenants this server holds (namespace `oauth_<REGION>`) | required |
| `TENANTS` | the tenants this server is the issuer for, comma-separated | required |
| `READ_LIMIT`, `READ_WINDOW_SECS` | metadata and key-set requests one client address may make per window | `300`, `60` |

```sh
cargo run --release -p tessari-oauth-node   # the tessaridb-oauth binary
curl --cacert cert.pem https://localhost:8443/acme/.well-known/oauth-authorization-server
```

At start the server provisions each tenant's database, makes a signing key for any tenant without one and then
checks every five minutes for keys due to rotate. Each read is counted per client address in TessariDB; past the limit
the answer is `429` with `Retry-After`, every counted answer carries `X-RateLimit-Limit`, `-Remaining` and `-Class`,
and when the store cannot count the request is refused with `503` rather than served. Logs are JSON on standard
output, filtered by `RUST_LOG` (`info` by default). On `SIGINT` or `SIGTERM` the listener stops accepting, the
requests in flight finish within 25 seconds, and the process exits 0.

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

Each test works in a namespace of its own, so the suite can run repeatedly against one node. The two TLS tests also need a
node serving TLS (`TESSARIDB_OAUTH_TEST_TLS_STORE`), the PEM of the authority that signed its certificate
(`TESSARIDB_OAUTH_TEST_TLS_AUTHORITY`) and the PEM of an unrelated one (`TESSARIDB_OAUTH_TEST_TLS_OTHER_AUTHORITY`).
Without an authority the server reaches its store only at `127.0.0.1` or `[::1]`.

## Licence

Business Source License 1.1 — see [LICENSE](LICENSE). Production use is permitted, including commercial use,
except providing the software to third parties as a hosted identity service or reselling it. Each version
converts to the Apache License 2.0 on its Change Date.
