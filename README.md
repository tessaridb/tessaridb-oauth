<div align="center">

<img src="assets/logo/tessaridb-oauth-mark-256.png" alt="" width="112" height="112">

# TessariDB OAuth

**Sign-in for your own applications, with every piece of its state in TessariDB.**

An OAuth 2.1 authorization server and OpenID provider written in Rust. One binary carries the protocol
endpoints, the users' account portal and an embedded admin panel on its own listener; tenants, users, clients,
codes, grants, keys and the audit trail are records in a TessariDB cluster.

[![release](https://img.shields.io/badge/release-0.1.0-6B5FD1?style=flat-square)](#status)
[![licence](https://img.shields.io/badge/licence-BUSL--1.1-6B5FD1?style=flat-square)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.98%2B-6B5FD1?style=flat-square)](#building-and-checking)

[oauth.tessaridb.com](https://oauth.tessaridb.com) · [docs](https://docs.tessaridb.com/oauth) ·
[tessaridb.com](https://tessaridb.com) · [TessariDB](https://github.com/tessaridb/tessaridb)

</div>

> [!NOTE]
> **0.1.0, the first release.** Everything listed under [Status](#status) is served by the binary and covered by
> tests. The configuration and the HTTP surface may still change in a minor release before 1.0.

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
| Release | 0.1.0, image `tessaridb/oauth:0.1.0` |
| Served | per-tenant discovery and key set; authorization (with PAR), token (code, refresh, client credentials), revocation, UserInfo, RP-initiated and back-channel logout; sign-in with password, TOTP, recovery codes and passkeys; password reset, enrolment links, address verification, changes of sign-in address and sign-in notices by mail, worded per company; self-registration under company policy; consent; the account portal and its API; the admin console; signing-key rotation; per-address limits; the audit trail; regions |
| Licence | BUSL-1.1 (see [Licence](#licence)) |

## Documentation

| | |
|---|---|
| [Protocol endpoints](docs/protocol.md) | clients, authorization, tokens, revocation, UserInfo, logout, first password |
| [Account API](docs/account.md) | a user's own account, grants and sessions |
| [Admin console](docs/admin-console.md) | the console's API and pages, operator roles in use, the audit trail |
| [How the server runs](docs/server.md) | start-up, limits and sign-in holds, the pages it carries, mail and password reset, logs and shutdown |
| [Regions](docs/regions.md) | home regions, peer directories and the redirect |
| [Platform operators](docs/operators.md) | the first operator's emergency path; incidents; a new KEK; backups |
| [Development](docs/development.md) | workspace layout and the live test suites |

## Running

The server reads its configuration from the environment when it starts, checks all of it, and refuses to start —
naming the variable — when anything is missing or does not fit. A `.env` file in the working directory is read
first, for development only.

| Variable (`TESSARIDB_OAUTH_…`) | Meaning | Default |
|---|---|---|
| `PUBLIC_URL` | the https base URL; tenant `acme`'s issuer is `<PUBLIC_URL>/acme`; its host is the passkey relying party, so changing the host retires every enrolled passkey | required |
| `PUBLIC_ADDRESS` | where the public listener binds | `0.0.0.0:8443` |
| `ADMIN_URL` | the admin console's base URL, at an origin other than `PUBLIC_URL`'s: https, or http on `127.0.0.1` or `[::1]` only; company `acme`'s console is `<ADMIN_URL>/admin/acme/` | required |
| `ADMIN_ADDRESS` | where the admin console's listener binds | `0.0.0.0:9443` |
| `ADMIN_TLS_CERT`, `ADMIN_TLS_KEY` | the admin console over TLS: its certificate chain and private key, PEM, both or neither. Without them the console is served in the clear, so keep it on a loopback address or behind a TLS terminator | unset (plain) |
| `TLS_CERT`, `TLS_KEY` | the public listener over TLS: its certificate chain and private key, PEM, both or neither. Without them it is served in the clear for a TLS terminator in front of it, which answers at the https `PUBLIC_URL` | unset (plain) |
| `TRUSTED_PROXIES` | the proxies in front of the server, IP addresses or `address/prefix` networks, comma-separated; a request from one of them is counted by the right-most `X-Forwarded-For` address that is not itself a listed proxy. From any other peer the header is ignored | none |
| `KEK` | the 32-byte key-encryption key file, mode 600 or 400; signing keys are stored sealed under it | required |
| `PEPPER` | the password pepper file, at least 32 bytes, mode 600 or 400; passwords are hashed under it and the sign-in counters named by keys derived from it | required |
| `PASSWORD_MEMORY_KIB`, `PASSWORD_ITERATIONS`, `PASSWORD_PARALLELISM` | the Argon2id cost of new password hashes; a value below the floor stops the start | `65536`, `3`, `1` |
| `PASSWORD_CONCURRENCY` | password hashes or checks run at once, each holding the cost's memory | `4` |
| `BREACHED_PASSWORDS_URL` | where a new password is looked up among passwords seen in breaches: an https range-query base ending in `/`, sent the first five hex digits of the password's SHA-1 and nothing else; `off` turns the lookup off | `https://api.pwnedpasswords.com/range/` |
| `STORE`, `STORE_USER`, `STORE_PASSWORD` | the TessariDB node's wire address and the account the server signs in with; the node runs TessariDB `0.38.2` or later | required |
| `STORE_AUTHORITY` | the PEM the node's certificate must lead to; without it only a loopback store is reached | none |
| `STORE_CONNECTIONS` | connections to the store at most | `16` |
| `REGION` | the region whose tenants this server holds (namespace `oauth_<REGION>`) | required |
| `TENANTS` | the companies (tenants) created and activated at start, comma-separated; a company an operator suspended stays suspended | required |
| `PEERS` | the other regions, `region=host:port` comma-separated, each its own TessariDB store; a company one of them serves is sent there | none |
| `PEER_USER`, `PEER_PASSWORD` | the account each other region's store holds for reading its directory; required with `PEERS` | none |
| `PEER_AUTHORITY` | the PEM the other regions' certificates must lead to; without it only loopback stores are reached | none |
| `READ_LIMIT`, `READ_WINDOW_SECS` | metadata, key-set and UserInfo requests one client address may make per window | `300`, `60` |
| `TOKEN_LIMIT`, `TOKEN_WINDOW_SECS` | token requests one client address may make per window | `60`, `60` |
| `AUTHORIZE_LIMIT`, `AUTHORIZE_WINDOW_SECS` | authorization requests one client address may make per window | `120`, `60` |
| `LOGIN_LIMIT`, `LOGIN_WINDOW_SECS` | sign-in steps one client address may post per window | `30`, `60` |
| `SMTP_URL` | the mail relay for password-reset links and sign-in notices: `smtps://host[:port]` (TLS from the start, port 465), `smtp://host[:port]` (STARTTLS required, port 587), or `smtp://<loopback IP>:port?plain` in the clear on a loopback address only; no credentials in the URL. Without it no mail is sent and a password reset answers `503` | unset (no mail) |
| `SMTP_FROM` | the sender, `address` or `Name <address>`; required with `SMTP_URL` | none |
| `SMTP_USER`, `SMTP_PASSWORD_FILE` | the relay account, both or neither; the password file must be mode 600 or 400 | none |
| `SMTP_AUTHORITY` | the PEM the relay's certificate must lead to; without it the system's roots are used | none |

```sh
cargo run --release -p tessari-oauth-node   # the tessaridb-oauth binary
curl http://localhost:8443/acme/.well-known/oauth-authorization-server
```

### In a container

The image `tessaridb/oauth` carries the server alone, for `linux/amd64` and `linux/arm64`. It listens on 8443
(public) and 9443 (admin console) and runs as the user `65532`, which must own the two key files and be the only one
able to read them:

```sh
head -c 32 /dev/urandom > kek && head -c 32 /dev/urandom > pepper
chmod 400 kek pepper && sudo chown 65532:65532 kek pepper
docker run -d --name oauth -p 8443:8443 -p 127.0.0.1:9443:9443 \
  -v "$PWD/kek:/keys/kek:ro" -v "$PWD/pepper:/keys/pepper:ro" \
  -e TESSARIDB_OAUTH_KEK=/keys/kek -e TESSARIDB_OAUTH_PEPPER=/keys/pepper \
  -e TESSARIDB_OAUTH_PUBLIC_URL=https://id.example.com -e TESSARIDB_OAUTH_ADMIN_URL=https://admin.example.com \
  -e TESSARIDB_OAUTH_STORE=db.example.com:9080 -e TESSARIDB_OAUTH_STORE_USER=oauth \
  -e TESSARIDB_OAUTH_STORE_PASSWORD -e TESSARIDB_OAUTH_STORE_AUTHORITY=/keys/store-ca.pem \
  -v "$PWD/store-ca.pem:/keys/store-ca.pem:ro" \
  -e TESSARIDB_OAUTH_REGION=eu -e TESSARIDB_OAUTH_TENANTS=acme tessaridb/oauth:0.1.0
```

Behind a reverse proxy, the proxy holds the certificate for `PUBLIC_URL`, passes requests on in the clear, and
appends the client's address to `X-Forwarded-For`; list its address in `TRUSTED_PROXIES`, or every client is counted
as the proxy and one client's failed sign-ins hold everyone's. Keep the plain listener reachable from the proxy
alone, since passwords and tokens cross it.

The server records its configured companies, provisions them and serves them at once; what it does after that is
in [How the server runs](docs/server.md). The first operator of a new installation comes from the emergency path:

```sh
tessaridb-oauth bootstrap-operator --email root@example.com
```

See [Platform operators](docs/operators.md) and, for more than one region, [Regions](docs/regions.md).

## Building and checking

A Cargo workspace on Rust 1.98 (edition 2024).

```sh
cargo build
cargo t          # every library and integration test
cargo lint       # clippy over all targets with warnings denied
cargo fmt --all --check
cargo deny check # licences, advisories, sources
```

Tests that need a TessariDB node are marked `ignored`; how to run them is in [Development](docs/development.md).

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
