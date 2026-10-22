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
> **Users can sign in through it, but nobody can create an account through it yet.**
> The binary serves each tenant's server metadata (RFC 8414, also served as the OpenID Provider configuration) and key
> set (RFC 7517) over TLS, its authorization, pushed authorization request, token, revocation and UserInfo endpoints,
> the sign-in and consent pages, ID tokens, and the account API a signed-in user reads and manages their own sessions
> and grants with, it rotates the tenants' signing keys and tells clients when a session ends. Accounts and their
> factors are not yet created or changed through any served surface; the account portal page and the admin panel come
> next. No release has been cut. Apart from the [Status](#status) section and the endpoints described below, this
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
| Served | metadata and key set per tenant; `/oauth2/authorize` (with `prompt` and `max_age`), `/oauth2/par`, `/oauth2/token` (authorization code, refresh token, client credentials; an ID token for `openid`), `/oauth2/revoke`, `/oauth2/userinfo` (subject only), `/oauth2/logout` (RP-initiated) and back-channel logout to registered clients; the sign-in page with password, TOTP, recovery-code and passkey steps, the account page, password hashing (Argon2id over a peppered HMAC, at a measured cost) and sign-in holds per account, address and credential pair that back off and never lock out, and the consent page; the session at this issuer; the account API (`/account/api`: the user's account and factors, sessions, grants); signing-key rotation; per-address limits; the audit trail |
| Built, not served yet | creating accounts and enrolling or changing factors (TOTP, recovery codes, passkey registration); new-password rules |
| Planned | the account portal page, the admin panel, a two-factor policy per tenant, companies with their own administrators, more regions |
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
`state` and `iss` (RFC 9207). A valid request is kept for ten minutes and the browser is sent to `<issuer>/login`
carrying only the kept request's id. A request with `prompt=none` asks for no page: without a session cookie it is
refused with `login_required`; with one it is kept the same way and sent straight to
`<issuer>/oauth2/authorize/resume`, which answers it from the session with a code, or at its redirect URI with
`login_required` (no live session, or one older than `max_age`), `consent_required` or `interaction_required`; each
refusal is recorded. Where the company's two-factor policy is `required` and the account holds no second factor, no
code is issued: the browser is sent to `<issuer>/account` to add one (a `prompt=none` request gets
`interaction_required`), and the request waits until then.

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

A code granted `openid` also redeems for an ID token (OpenID Connect Core §3.1.3.3), a JWT of type `JWT` signed by
the same key and addressed to the client alone. It states how the user signed in, as the code recorded it when it
was issued: `auth_time`, `acr`, `amr` derived from the methods verified, `sid` (the session's public id, never its
cookie), the request's `nonce` when one was sent, and `at_hash` binding it to the access token beside it, under the
same pairwise `sub`. It carries no profile or contact data and lives five minutes.

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

### Logout: `GET|POST <issuer>/oauth2/logout`

A client signs a user out here (OpenID Connect RP-Initiated Logout 1.0) by sending the browser with an
`id_token_hint`: an ID token this tenant issued to it, however old. Without a hint that reads as one, or with a
`client_id` other than the hint's own, nothing is ended and the browser stays on a refusal page. The session the
browser's cookie holds is ended only when it is the session the hint names, the cookie is cleared, and the ending is
recorded in the audit trail. The browser goes back only to a `post_logout_redirect_uri` the client registered, matched
exactly, with its `state`; any other value is never followed and a signed-out page is shown here instead. A cross-site
`POST` carries no session cookie (`SameSite=Lax`), so a client signs users out with a `GET` redirect. Discovery
advertises the endpoint as `end_session_endpoint`.

### Back-channel logout

When a session ends here, by the logout endpoint, a sign-out from the account API or a revocation that ends sessions,
every client that received tokens in that session and registered a `backchannel_logout_uri` is told (OpenID Connect
Back-Channel Logout 1.0). The ending and the owed notice are written in one commit, so a crash between them loses
nothing. Each client gets its own logout token, a JWT of type `logout+jwt` signed with the tenant's key, addressed to
that client, naming the session (`sid`) and the subject that client knows the user by, and valid for two minutes. It
arrives as `POST` with the form field `logout_token`; `200` or `204` means told. The URI must be `https`, an address
in the link-local range (cloud metadata services among them) is never called, a redirect is never followed, and each
client has five seconds. A client that was not told is tried again after 5 s, then twice as long each time up to an
hour, at most ten times. A session that simply expires tells nobody; its clients' own sessions should expire with it.

### First password: `POST <issuer>/login/api/enroll`

A user an operator created sets a first password here with `{"code": "<code>", "password": "<password>"}`, the
one-time code the operator handed them. A code is kept only as its digest, lasts 72 hours, and a newer code for the
same user replaces it; a code that was never issued, was spent, was replaced or has lapsed gets the same
`400 code_rejected`. The password follows the rules for an account whose password is its only factor, and a refused
password does not spend the code. An account that already has a password keeps it (`409 already_enrolled`). The
answer is `204`; no session is opened, and the user then signs in as anyone does.

### Your account: `<issuer>/account/api/me`

`GET <issuer>/account/api/me` answers the signed-in user's own account: the address they sign in with and whether it is
verified, and their sign-in factors as facts: whether a password is set, whether an authenticator app is enrolled, how
many recovery codes are left, and each passkey by its credential id, with when it was registered and whether it may be
synced, and the company's two-factor policy as `two_factor`. No secret, hash or key is part of it. Like the routes below
it needs the session cookie, is counted under the account limit and is never cached.

`POST <issuer>/account/api/passkeys/remove` with `{"id": "<credential id>"}` removes one of the user's own passkeys.
Changing how an account signs in needs a sign-in from the last ten minutes that reached the level the account's
second factor gives (a password alone does not change an account that holds a passkey or an authenticator app),
otherwise `401 reauthentication_required`; the account's last way to sign in is refused with
`409 last_sign_in_method`. A removal signs out every other session of the user, revokes every refresh family the user
holds and is recorded, and the answer says when the access tokens already issued stop working.
`POST <issuer>/account/api/recovery-codes` with `{}` replaces every unspent recovery code with ten new ones, under the
same recent sign-in rule and with the same sign-outs: the codes are in that answer once and are never kept or
recorded in the clear. An authenticator app is enrolled in two steps under the same rule: `POST
<issuer>/account/api/totp/begin` with `{}` answers a new secret once, in base32 and as the `otpauth://` URI an app
scans, and keeps it sealed for that session for ten minutes; `POST <issuer>/account/api/totp/confirm` with
`{"code": "<six digits>"}` enrols it when the code comes from that secret, with the same sign-outs. A wrong code ends
the attempt (`400 code_rejected`, then `409 nothing_pending`), and an account that has an app already gets
`409 already_enrolled`. `POST <issuer>/account/api/totp/remove` with `{}` turns the app off under the same rule,
takes the unspent recovery codes with it and ends the same things; with no app it answers `{"removed": false}`.
Each company has a two-factor policy, `optional` until set: under `off` a sign-in asks no app code, no app is offered
(`409 not_offered`) and an app still held counts for nothing, so a password sign-in may turn it off; under `required`
the account's last second factor, app or passkey, is not removed (`409 second_factor_required`).
A passkey is added the same way: `POST <issuer>/account/api/passkeys/options` with `{}`
answers a registration challenge issued to that user alone, with the user's own passkeys to exclude and the user
verification it requires, and `POST <issuer>/account/api/passkeys/register` with the browser's `client_data_json`
and `attestation_object` spends that challenge once, checks the response against this issuer's relying party and
origin, stores the passkey and signs out the other sessions.
`POST <issuer>/account/api/password` with `{"password": "<new password>"}` sets a new password under the same rule
and with the same sign-outs. It must be at least fifteen characters, or eight when the account has an authenticator app
its company's policy asks for (a sign-in then always asks for its code), and must not be the account's own address, its
local part or the tenant's name; otherwise `400 password_rejected` with the rule it broke. The value is never echoed,
logged or recorded. Screening against a list of compromised passwords is not done yet.

### Your grants: `<issuer>/account/api/grants`

A signed-in user reads the grants they gave with `GET <issuer>/account/api/grants`: for each client still holding
one, the scopes, the resources and when it was given. `POST <issuer>/account/api/grants/revoke` with
`{"client_id": "<client>"}` ends that grant: the consent is withdrawn, which is recorded, and every refresh family
of that user at that client is revoked, so the client must ask again. The answer says how many families ended and
the time by which the access tokens it already holds stop working, at most five minutes on, because an access token
is never recalled. Both act for the session's own user and nobody else, need the session cookie (`401 session_required`
without it), take JSON only, are counted under their own limit and are never cached.

### Your sessions: `<issuer>/account/api/sessions`

`GET <issuer>/account/api/sessions` lists the signed-in user's live sessions at this issuer by their public id, with
when each signed in, when it was last used, the methods it signed in with, and which one is asking; never a cookie.
`POST <issuer>/account/api/sessions/end` with `{"sid": "<sid>"}` ends one of the user's own sessions (another
user's id ends nothing), and `POST <issuer>/account/api/sessions/end-all` with `{}` signs the user out everywhere:
every session, the asking one included, and every refresh family the user holds at any client. That answer says how
many of each ended and when the access tokens already issued stop working. Every ending is recorded in the audit
trail, and the same rules as the grant list apply: the session cookie, JSON only, their own limit, never cached.

### The admin console: `<ADMIN_URL>/admin/<company>`

An operator opens a company's console at `<ADMIN_URL>/admin/<company>/signin`, which sends the browser to that
company's own sign-in as the client `admin-console`, with PKCE, a `state` and a `nonce`. Every company has this client
registered, with no grant type, so nothing outside the server can redeem its codes. The return to
`<ADMIN_URL>/admin/<company>/callback` opens a console session only when the `state`, the issuer, the code and its
`nonce` all check out, the operator signed in with two factors, and they hold at least one current operator role. Any
other return gets one and the same refusal and is recorded in the audit trail.

The session is kept in an `HttpOnly`, `SameSite=Strict` cookie (`__Host-` and `Secure` over https). It lasts at most
8 hours, ends after 30 minutes unused, and ends with the company sign-in session it came from or when the operator's
last role is taken away. `GET <ADMIN_URL>/admin/<company>/api/me` names the operator and their roles, and
`POST <ADMIN_URL>/admin/<company>/signout` ends the session, accepted only from the console's own origin. Console
requests are counted per client address under the `LOGIN_LIMIT` and `LOGIN_WINDOW_SECS` numbers.

Every console route needs one operator role, and a refusal for a missing role is recorded. A change comes from the
console's own origin as JSON carrying the operator's `reason` (1 to 500 characters) and an `Idempotency-Key` header (16
to 128 letters, digits, `-` or `_`). A change is made once per operator and key; sent again within a day it gets the
first answer back, and the same key with another change is refused. Every change is recorded as `admin_action` with
the operator, the role, the change and the reason. `GET` and `PUT <ADMIN_URL>/admin/<company>/api/policy/two-factor`
(role `policy`) read and change the company's two-factor policy; a change names the policy it replaces in `expected`,
and when another change came first it is refused as `changed_meanwhile` and changes nothing.

`GET <ADMIN_URL>/admin/<company>/api/users?limit=&after=` (role `users`) lists the company's accounts in id order, at
most 100 a page (50 unless `limit` says), with `next` naming the cursor of the following page while one may follow
and no total; `?email=<address>` instead finds the one account that exact address signs in with, and
`GET .../api/users/<user>` reads one account. Every address in these answers is masked to its first character and
domain (`k***@acme.example`). `POST .../api/users/<user>/email/reveal` (role `users`, from the console's origin, with
a `reason`) shows one address whole, and is recorded as `admin_action` `users.reveal_email` with the operator and the
reason before it is shown; when the record cannot be written, nothing is shown.

`POST <ADMIN_URL>/admin/<company>/api/users/<user>/disable` and `.../enable` (role `users`) move an account between
`active` and `disabled`, each only from the other status (`changed_meanwhile` otherwise, `user_not_found` for an account
the company does not have). Disabling ends every session of the account, telling its clients through the back
channel, revokes every refresh family (recorded as `user_disabled`), and with the sessions ends any console session
of its own; its access tokens stop working by the `access_tokens_end_by` the answer gives. A disabled account cannot
sign in. Enabling gives back only that: nothing ended comes back.

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
| `ADMIN_URL` | the admin console's base URL, at an origin other than `PUBLIC_URL`'s: https, or http on `127.0.0.1` or `[::1]` only; company `acme`'s console is `<ADMIN_URL>/admin/acme` | required |
| `ADMIN_ADDRESS` | where the admin console's listener binds | `0.0.0.0:9443` |
| `ADMIN_TLS_CERT`, `ADMIN_TLS_KEY` | the admin console over TLS: its certificate chain and private key, PEM, both or neither. Without them the console is served in the clear, so keep it on a loopback address or behind a TLS terminator | unset (plain) |
| `TLS_CERT`, `TLS_KEY` | the listener's certificate chain and private key, PEM | required |
| `KEK` | the 32-byte key-encryption key file, mode 600 or 400; signing keys are stored sealed under it | required |
| `PEPPER` | the password pepper file, at least 32 bytes, mode 600 or 400; passwords are hashed under it and the sign-in counters named by keys derived from it | required |
| `PASSWORD_MEMORY_KIB`, `PASSWORD_ITERATIONS`, `PASSWORD_PARALLELISM` | the Argon2id cost of new password hashes; a value below the floor stops the start | `65536`, `3`, `1` |
| `PASSWORD_CONCURRENCY` | password hashes or checks run at once, each holding the cost's memory | `4` |
| `STORE`, `STORE_USER`, `STORE_PASSWORD` | the TessariDB node's wire address and the account the server signs in with | required |
| `STORE_AUTHORITY` | the PEM the node's certificate must lead to; without it only a loopback store is reached | none |
| `STORE_CONNECTIONS` | connections to the store at most | `16` |
| `REGION` | the region whose tenants this server holds (namespace `oauth_<REGION>`) | required |
| `TENANTS` | the companies (tenants) created and activated at start, comma-separated; a company an operator suspended stays suspended | required |
| `READ_LIMIT`, `READ_WINDOW_SECS` | metadata, key-set and UserInfo requests one client address may make per window | `300`, `60` |
| `TOKEN_LIMIT`, `TOKEN_WINDOW_SECS` | token requests one client address may make per window | `60`, `60` |
| `AUTHORIZE_LIMIT`, `AUTHORIZE_WINDOW_SECS` | authorization requests one client address may make per window | `120`, `60` |
| `LOGIN_LIMIT`, `LOGIN_WINDOW_SECS` | sign-in steps one client address may post per window | `30`, `60` |

```sh
cargo run --release -p tessari-oauth-node   # the tessaridb-oauth binary
curl --cacert cert.pem https://localhost:8443/acme/.well-known/oauth-authorization-server
```

At start the server records each configured company in the region's directory, provisions its database, registers
its admin console as the client `admin-console` of the company's issuer (redirected only to the console's own
callback, asking for nothing past `openid`, addressed to `<PUBLIC_URL>/<company>/admin`, and with no grant the token
endpoint will redeem) and makes it
active, makes a signing key for any company without one and then checks every five minutes for keys due to rotate.
Every node re-reads which companies are active every five seconds and serves exactly those: a company that is not
active answers `404`, like a name that was never a company.
Each read, authorization request, token request and sign-in step is
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
`iss`; otherwise the browser is sent to `<issuer>/consent`, and without a session to sign in again. A sign-in
older than the request's `max_age` in seconds, or any earlier sign-in under `prompt=login`, is done again first. The consent
page reads `GET <issuer>/login/api/consent?interaction=<id>`, which lists only the scopes and resources not yet
granted, and posts the user's `allow` or `deny`: allowing records the grant before a code exists, denying grants
nothing and answers `access_denied`, and either answer is the redirect-URI address the browser goes on to. A pending
authorization belongs to the browser that brought it to `/oauth2/authorize`, by the cookie `__Host-tessari-browser`
(kept when the browser has one, drawn otherwise): another browser holding the request's id cannot sign in for it,
answer its consent or receive its code.

The sign-in, consent and account pages are served by the binary itself at `<issuer>/login`, `<issuer>/consent` and
`<issuer>/account`, with their script, style and mark under `<issuer>/assets/`. The account page shows the signed-in
user's address, how the account signs in, where it is signed in and which applications hold access; it signs out one
session or every session after a confirmation, takes an application's access back, saying when the tokens it already
holds stop working, changes the password, issues new recovery codes shown once, turns on an authenticator app from a
key shown once, and adds or removes passkeys. Without a session it offers a sign-in
(`<issuer>/login?return=account`) that comes back to it, and it offers the same sign-in when a change needs a recent
one. They load nothing from anywhere else, talk only to this server, submit no form, cannot be framed, follow the
system's light or dark theme and work from the keyboard alone; a passkey is offered wherever the browser supports
one. Their TypeScript source is in `crates/tessari-oauth-api/pages/`, and its built output is committed to
`crates/tessari-oauth-api/assets/`, so building the server needs no Node. After changing the source, `npm install`
once and `npm run build` there; `npm run verify` type-checks, runs the page tests and fails when the committed
assets differ from a rebuild.

Logs are JSON on standard output, filtered by
`RUST_LOG` (`info` by default). On `SIGINT` or `SIGTERM` the listeners stop accepting, the requests in flight
finish within 25 seconds, and the process exits 0.

### The first platform operator

```sh
tessaridb-oauth bootstrap-operator --email root@example.com
```

This is the emergency path, for the first operator after installation or for one whose access is lost. It reads
the same environment as the server and needs only the store. It creates and activates the `system` company when
there is none, finds or registers the account with that address there, and gives it the operator roles `companies`
and `users`. When the account has no password yet it prints a one-time enrolment code for
`POST <PUBLIC_URL>/system/login/api/enroll`; an account that has a password keeps it. The code is shown once and
never logged, so run the command at a terminal rather than under a supervisor that collects its output. Every run
is logged at `ERROR` as `break_glass` and recorded on the `system` company's audit trail.

Operator roles are held per company and per task: `users`, `clients`, `policy`, `audit`, and `companies`, which only
users of the `system` company may hold. A grant names who gave it and why, may carry an expiry after which it no
longer counts, and is refused when it names its own holder as the giver. Every grant and revoke is on the company's
audit trail.

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

Each test works in a namespace of its own; a run removes the namespaces earlier runs left before its first test
starts, so the node holds at most one run's. The suite can run repeatedly against one node. The two TLS
tests also need a node serving TLS (`TESSARIDB_OAUTH_TEST_TLS_STORE`), the PEM of the authority that signed its
certificate (`TESSARIDB_OAUTH_TEST_TLS_AUTHORITY`) and the PEM of an unrelated one
(`TESSARIDB_OAUTH_TEST_TLS_OTHER_AUTHORITY`).
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
