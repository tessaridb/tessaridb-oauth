<div align="center">

<img src="assets/logo/tessaridb-oauth-mark-256.png" alt="" width="112" height="112">

# TessariDB OAuth

**Sign-in for your own applications, with every piece of its state in TessariDB.**

An OAuth 2.1 authorization server and OpenID provider written in Rust. One binary carries the protocol
endpoints, the users' account portal and an embedded admin panel on its own listener; tenants, users, clients,
codes, grants, keys and the audit trail are records in a TessariDB cluster.

[![status](https://img.shields.io/badge/status-in%20development-6B5FD1?style=flat-square)](#status)
[![licence](https://img.shields.io/badge/licence-BUSL--1.1-6B5FD1?style=flat-square)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.98%2B-6B5FD1?style=flat-square)](#building-and-checking)

[tessaridb.com](https://tessaridb.com) · [TessariDB](https://github.com/tessaridb/tessaridb) ·
[docs](https://docs.tessaridb.com)

</div>

> [!NOTE]
> **It issues tokens to clients, but nobody can sign in through it yet.**
> The binary serves each tenant's server metadata (RFC 8414) and key set (RFC 7517) over TLS, its authorization,
> pushed authorization request, token, revocation and UserInfo endpoints, and rotates the tenants' signing keys.
> The sign-in page the authorization endpoint hands over to, the account portal and the admin panel are not served
> yet. No release has been cut. Apart from the [Status](#status) section and the endpoints described below, this
> page describes what the project is for, not a working system.

## What it is for

- **Sign-in and single sign-on** for your own applications, with one issuer per tenant.
- **Users look after themselves** — their profile, sessions, connected applications and security settings — in the
  account portal.
- **Administrators manage** tenants, users, clients and keys from the admin panel, with every action recorded.
- **One home region per tenant.** Each tenant's identity data lives in one region; requests for it elsewhere are
  redirected, never proxied.
- **State in TessariDB.** Codes, grants, consents, refresh families, sessions, sealed keys, replay and throttle
  counters and the audit trail are that database's records, transactions and spaces, not a second store kept beside
  it.

## The promises it is being designed to keep

These are design commitments. The ones marked **in place** are implemented and covered by tests; the rest are not
claimed until a test backs them.

- **One browser flow.** Authorization code with PKCE `S256` (RFC 7636); implicit, hybrid token-returning and
  password grants will not be offered. **In place.**
- **Redirect URIs matched exactly**, with only the native-app loopback port exception (RFC 8252 §7.3). **In place.**
- **A code redeems once.** Of any number of simultaneous redemptions exactly one succeeds and the rest are reported
  as replays. **In place.**
- **A reused refresh token revokes its family.** **In place.**
- **Tokens bound to a key when the client asks** — DPoP (RFC 9449), keys named by their JWK thumbprint (RFC 7638).
  **In place.**
- **Nothing secret in a log.** A message never carries a token, code, verifier, assertion or proof. **In place.**
- **Every issuance is on the record**, and one that cannot be recorded is not answered. **In place.**
- **A second factor that is really there.** Passkeys, TOTP and recovery codes, a user's own choice or a tenant's
  rule, never removed by an email alone.

## Status

| | |
|---|---|
| Stage | in development, no release |
| Served | metadata and key set per tenant; `/oauth2/authorize`, `/oauth2/par`, `/oauth2/token` (authorization code, refresh token, client credentials), `/oauth2/revoke`, `/oauth2/userinfo` (subject only); signing-key rotation; per-address limits; the audit trail |
| Built, not served yet | user accounts with unique addresses; new-password rules; password hashing (Argon2id over a peppered HMAC, at a measured cost); TOTP (RFC 6238) with each code accepted once; recovery codes, each spent once; sign-in holds per account, address and credential pair that back off and never lock out; passkeys — registration and assertion checks for EdDSA, ES256 and RS256 keys, credentials kept one owner per id, counters advanced by compare-and-set, challenges spent once |
| Planned | the sign-in page and its ceremony, the account portal, the admin panel, a two-factor policy per tenant, companies with their own administrators, more regions |
| Licence | BUSL-1.1 (see [Licence](#licence)) |

## How it behaves

### Clients

Confidential clients authenticate with `private_key_jwt`: an Ed25519 or ES256 assertion signed by a key the client
registered, addressed to the tenant's issuer alone, and valid for at most five minutes. Each assertion is accepted
once: its `jti` is recorded in a TessariDB space until it could no longer be accepted, and a second presentation is
refused as a replay. A client redeems only the grant types it registered.

DPoP proofs (RFC 9449) are checked the same way: typed `dpop+jwt`, signed by the public key they carry under the
server's algorithms, bound to this method and URI, at most a minute old, and accepted once per key; the token they
accompany is bound to that key's RFC 7638 thumbprint.

### Authorization — `GET|POST <issuer>/oauth2/authorize`

The authorization endpoint (RFC 6749 §4.1.1) judges a request in a fixed order. Until the client is known and the
redirect URI is one it registered, a refusal is shown on a page at the server and sent nowhere, so a URI written
into a forged request never receives an answer; every later refusal goes back to the registered URI with `error`,
`state` and `iss` (RFC 9207). A request with `prompt=none` asks for no page and is refused with `login_required`. A
valid request is kept for ten minutes and the browser is sent to `<issuer>/login` carrying only the kept request's
id.

A client may instead push those parameters to `POST <issuer>/oauth2/par` (RFC 9126), authenticating exactly as at
the token endpoint; they are judged as the authorization endpoint judges them, every refusal answered to the client,
and the answer names them by a `request_uri` for sixty seconds. The browser then brings only `client_id` and that
`request_uri` to the authorization endpoint, where the pushed request is claimed once, by the client that pushed
it, and nothing else in the URL is read. Pushing is advertised in the metadata and not required.

Consent is a record per user and client holding the granted scopes, resources and consent policy version; a request
outside it is answered with exactly what must be asked, simultaneous grants are all kept, and a revocation records
who made it.

### Tokens — `POST <issuer>/oauth2/token`

The token endpoint redeems authorization codes (RFC 6749 §4.1.3). It reads a form body of at most 16 KiB, refuses a
repeated parameter or more than one client authentication method, and authenticates the client by its pinned method
before it reads the code. Authorization codes are stored by their SHA-256 digest only and are spent with one
conditional write. The code is spent first and its bindings checked after, so a code redeems once whatever the
outcome; a code presented again is refused and revokes the refresh family it started.

The access token is an RFC 9068 JWT addressed to one resource, carrying only `iss`, `aud`, `sub`, `client_id`,
`scope`, `iat`, `exp` and `jti`, valid for five minutes — the time a revoked grant can still be used — with `sub` a
pairwise identifier per client.

A client registered for refresh tokens also receives one, and redeems it at the same endpoint (RFC 6749 §6). Refresh
tokens rotate on every use and are kept as digests only. The request is judged on the family's grant before the
token is rotated, so a refused refresh leaves the token usable; the access token may be narrowed to fewer scopes or
one of the grant's resources but never widened, and a token presented after it was rotated revokes its whole family.
A refresh token lives at most 14 days unused and 30 days in all.

A confidential client registered for `client_credentials` (RFC 6749 §4.4; a public client cannot register it) gets
its own token: it names its scopes within its ceiling — never `openid`, since no user signed in — and one of the
resources it registered, the token's `sub` is the client itself (RFC 9068 §2.2), and no refresh token is issued.

A request carrying a DPoP proof — one `DPoP` header, verified for this endpoint and spent once, after every other
check — receives a `DPoP` token naming the proof's key in `cnf.jkt`; a client registered with
`dpop_bound_access_tokens` is refused without one, and a public client's refresh token keeps needing the key it was
issued to. Without a proof the token is `Bearer`. Refusals carry the `error` code alone.

### Revocation — `POST <issuer>/oauth2/revoke`

The revocation endpoint (RFC 7009) authenticates the client exactly as the token endpoint does and revokes a refresh
token together with its whole family. An unknown or already revoked token is answered `200` like a revoked one,
another client's token is refused with `invalid_grant` and left usable, and a `token_type_hint` is only a hint. An
access token is refused with `unsupported_token_type`: it is never recalled and stays valid for at most its five
minutes. Discovery advertises the endpoint and its authentication methods.

### UserInfo — `GET|POST <issuer>/oauth2/userinfo`

UserInfo (OpenID Connect Core §5.3) answers an access token addressed to that URL — a client that calls it registers
the URL as one of its resources and names it as `resource` — and carrying `openid`, with the token's subject
(`{"sub": …}`) and nothing more yet: profile and contact claims will be released per scope once the account
endpoints serve them. The token is read from the `Authorization` header alone, as `Bearer`, or as `DPoP` with a proof
over that token (`ath`, RFC 9449 §7.1) that is spent once; a bound token is refused as a bearer token. Every bad
token gets the same `401` with `error="invalid_token"` in `WWW-Authenticate`, a token without `openid` a `403` with
`error="insufficient_scope"`, and none of the answers is cached. A token from the client credentials grant never
carries `openid`, so it never reaches UserInfo. Discovery advertises the endpoint.

### The audit trail

Every outcome at the token and revocation endpoints, and every refusal at the authorization and UserInfo endpoints,
is appended to an audit topic in the tenant's TessariDB database, which the store itself refuses to rewrite or delete
from, and kept for 400 days: what was issued — client, user, subject, scopes, audience, the access token's `jti`, the
authentication method and the bound key — what was refused and why, a replayed code, a reused refresh token and a
revocation. A message never carries a token, code, verifier, assertion or proof. An issuance that cannot be recorded
is not answered; a refusal is answered either way.

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
| `PUBLIC_URL` | the https base URL; tenant `acme`'s issuer is `<PUBLIC_URL>/acme`; its host is the passkey relying party, so changing the host retires every enrolled passkey | required |
| `PUBLIC_ADDRESS` | where the public listener binds | `0.0.0.0:8443` |
| `TLS_CERT`, `TLS_KEY` | the listener's certificate chain and private key, PEM | required |
| `KEK` | the 32-byte key-encryption key file, mode 600 or 400; signing keys are stored sealed under it | required |
| `PEPPER` | the password pepper file, at least 32 bytes, mode 600 or 400; passwords are hashed under it and the sign-in counters named by keys derived from it | required |
| `PASSWORD_MEMORY_KIB`, `PASSWORD_ITERATIONS`, `PASSWORD_PARALLELISM` | the Argon2id cost of new password hashes; a value below the floor stops the start | `65536`, `3`, `1` |
| `PASSWORD_CONCURRENCY` | password hashes or checks run at once, each holding the cost's memory | `4` |
| `STORE`, `STORE_USER`, `STORE_PASSWORD` | the TessariDB node's wire address and the account the server signs in with | required |
| `STORE_AUTHORITY` | the PEM the node's certificate must lead to; without it only a loopback store is reached | none |
| `STORE_CONNECTIONS` | connections to the store at most | `16` |
| `REGION` | the region whose tenants this server holds (namespace `oauth_<REGION>`) | required |
| `TENANTS` | the tenants this server is the issuer for, comma-separated | required |
| `READ_LIMIT`, `READ_WINDOW_SECS` | metadata, key-set and UserInfo requests one client address may make per window | `300`, `60` |
| `TOKEN_LIMIT`, `TOKEN_WINDOW_SECS` | token requests one client address may make per window | `60`, `60` |
| `AUTHORIZE_LIMIT`, `AUTHORIZE_WINDOW_SECS` | authorization requests one client address may make per window | `120`, `60` |
| `LOGIN_LIMIT`, `LOGIN_WINDOW_SECS` | sign-in steps one client address may post per window | `30`, `60` |

```sh
cargo run --release -p tessari-oauth-node   # the tessaridb-oauth binary
curl --cacert cert.pem https://localhost:8443/acme/.well-known/oauth-authorization-server
```

At start the server provisions each tenant's database, makes a signing key for any tenant without one and then
checks every five minutes for keys due to rotate. Each read, authorization request, token request and sign-in step is
counted per client address in TessariDB, under separate limits; past the limit the answer is `429` with
`Retry-After`, every counted answer carries `X-RateLimit-Limit`, `-Remaining` and `-Class`, and when the store
cannot count the request is refused with `503` rather than served. A wrong password is also counted against the
address being signed in to, the client address and the pair of the two (a wrong one-time or recovery code against
the first two); past a few failures that key is held for a
short, growing time that ends by itself (never a lockout), and a wrong password and an address with no account get
the same `401`. A passkey answers its sign-in's challenge once: one that verified its user is a whole sign-in and
names the account itself, one where a password came first stands as the second factor, and a passkey of another
account, a foreign origin or a counter that did not move forward gets that same `401` and is counted. The step that
completes a sign-in ends it and opens the user's session under a cookie of its own, `__Host-tessari-session`, drawn
at that moment (a session lasts a working day without use and a week at most), and clears the sign-in cookie.
The browser then continues at `<issuer>/oauth2/authorize/resume`: when the user's consent to the client covers
every scope and resource asked for, the request is answered once at its redirect URI with a code, its `state` and
`iss`; otherwise the browser is sent to `<issuer>/consent`, and without a session to sign in again.
Logs are JSON on standard output, filtered by
`RUST_LOG` (`info` by default). On `SIGINT` or `SIGTERM` the listener stops accepting, the requests in flight
finish within 25 seconds, and the process exits 0.

## Building and checking

A Cargo workspace on Rust 1.98 (edition 2024).

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

Each test works in a namespace of its own, so the suite can run repeatedly against one node. The two TLS tests also
need a node serving TLS (`TESSARIDB_OAUTH_TEST_TLS_STORE`), the PEM of the authority that signed its certificate
(`TESSARIDB_OAUTH_TEST_TLS_AUTHORITY`) and the PEM of an unrelated one (`TESSARIDB_OAUTH_TEST_TLS_OTHER_AUTHORITY`).
Without an authority the server reaches its store only at `127.0.0.1` or `[::1]`.

## Branches

`dev` is where development happens. `main` will carry releases and move only by merging `dev` at a release, with
each release tagged there.

## Licence

TessariDB OAuth is licensed under the [Business Source License 1.1](LICENSE). Production use is free, including use
by and within a commercial company. Two things need a commercial licence from the Licensor:
- providing TessariDB OAuth to third parties as a hosted or managed identity, authentication or authorization
  service;
- selling, reselling, renting or sublicensing it.

On the Change Date in [`LICENSE`](LICENSE) each version converts to the Apache License, Version 2.0. For other
arrangements, write to licensing@tessaridb.com.
