# Protocol endpoints

What each endpoint of a tenant's issuer accepts, refuses and answers. A tenant's issuer is `<PUBLIC_URL>/<tenant>`.

## Clients

Confidential clients authenticate with `private_key_jwt`: an Ed25519 or ES256 assertion signed by a key the client
registered, addressed to the tenant's issuer alone, and valid for at most five minutes. Each assertion is accepted
once: its `jti` is recorded in a TessariDB space until it could no longer be accepted, and a second presentation is
refused as a replay. A client redeems only the grant types it registered.

DPoP proofs (RFC 9449) are checked the same way: typed `dpop+jwt`, signed by the public key they carry under the
server's algorithms, bound to this method and URI, at most a minute old, and accepted once per key; the token they
accompany is bound to that key's RFC 7638 thumbprint.

## Authorization — `GET|POST <issuer>/oauth2/authorize`

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

## Tokens — `POST <issuer>/oauth2/token`

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

## Revocation — `POST <issuer>/oauth2/revoke`

The revocation endpoint (RFC 7009) authenticates the client exactly as the token endpoint does and revokes a refresh
token together with its whole family. An unknown or already revoked token is answered `200` like a revoked one,
another client's token is refused with `invalid_grant` and left usable, and a `token_type_hint` is only a hint. An
access token is refused with `unsupported_token_type`: it is never recalled and stays valid for at most its five
minutes. Discovery advertises the endpoint and its authentication methods.

## UserInfo — `GET|POST <issuer>/oauth2/userinfo`

UserInfo (OpenID Connect Core §5.3) answers an access token addressed to that URL — a client that calls it registers
the URL as one of its resources and names it as `resource` — and carrying `openid`, with the token's subject
(`{"sub": …}`). A token that also carries `groups` gets `groups`, the ids of the company's groups its user is in, and
`roles`, the roles those groups carry, each sorted and read from the store at that moment, so a membership removed a
moment ago is gone from the next answer; these two claims appear nowhere else, not in the ID token and not in the
access token. Profile and contact claims will be released per scope once the account endpoints serve them. Adding
`groups` raised the consent policy to version 2, so every earlier grant is asked for once more.
The token is read from the `Authorization` header alone, as `Bearer`, or as `DPoP` with a proof
over that token (`ath`, RFC 9449 §7.1) that is spent once; a bound token is refused as a bearer token. Every bad
token gets the same `401` with `error="invalid_token"` in `WWW-Authenticate`, a token without `openid` a `403` with
`error="insufficient_scope"`, and none of the answers is cached. A token from the client credentials grant never
carries `openid`, so it never reaches UserInfo. Discovery advertises the endpoint.

## Logout: `GET|POST <issuer>/oauth2/logout`

A client signs a user out here (OpenID Connect RP-Initiated Logout 1.0) by sending the browser with an
`id_token_hint`: an ID token this tenant issued to it, however old. Without a hint that reads as one, or with a
`client_id` other than the hint's own, nothing is ended and the browser stays on a refusal page. The session the
browser's cookie holds is ended only when it is the session the hint names, the cookie is cleared, and the ending is
recorded in the audit trail. The browser goes back only to a `post_logout_redirect_uri` the client registered, matched
exactly, with its `state`; any other value is never followed and a signed-out page is shown here instead. A cross-site
`POST` carries no session cookie (`SameSite=Lax`), so a client signs users out with a `GET` redirect. Discovery
advertises the endpoint as `end_session_endpoint`.

## Back-channel logout

When a session ends here, by the logout endpoint, a sign-out from the account API or a revocation that ends sessions,
every client that received tokens in that session and registered a `backchannel_logout_uri` is told (OpenID Connect
Back-Channel Logout 1.0). The ending and the owed notice are written in one commit, so a crash between them loses
nothing. Each client gets its own logout token, a JWT of type `logout+jwt` signed with the tenant's key, addressed to
that client, naming the session (`sid`) and the subject that client knows the user by, and valid for two minutes. It
arrives as `POST` with the form field `logout_token`; `200` or `204` means told. The URI must be `https`, an address
in the link-local range (cloud metadata services among them) is never called, a redirect is never followed, and each
client has five seconds. A client that was not told is tried again after 5 s, then twice as long each time up to an
hour, at most ten times. A session that simply expires tells nobody; its clients' own sessions should expire with it.

## First password: `POST <issuer>/login/api/enroll`

A user an operator created sets a first password here with `{"code": "<code>", "password": "<password>"}`, the
one-time code the operator handed them. A code is kept only as its digest, lasts 72 hours, and a newer code for the
same user replaces it; a code that was never issued, was spent, was replaced or has lapsed gets the same
`400 code_rejected`. The password follows the rules for an account whose password is its only factor, and a refused
password does not spend the code. An account that already has a password keeps it (`409 already_enrolled`). The
answer is `204`; no session is opened, and the user then signs in as anyone does.
