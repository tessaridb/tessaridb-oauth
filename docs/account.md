# Account API

What a signed-in user reads and changes about their own account under `<issuer>/account/api`.

## Your account: `<issuer>/account/api/me`

`GET <issuer>/account/api/me` answers the signed-in user's own account: the address they sign in with and whether it is
verified, and their sign-in factors as facts: whether a password is set, whether an authenticator app is enrolled, how
many recovery codes are left, and each passkey by its credential id, with when it was registered and whether it may be
synced, and the company's two-factor policy as `two_factor`. No secret, hash or key is part of it. Like the routes below
it needs the session cookie, is counted under the account limit and is never cached.

`POST <issuer>/account/api/me/verify` with `{}` mails a link that verifies that address: `202` once the mail is queued,
`204` and no mail when the address is verified already, and `503 mail_unavailable` when the server has no mail relay.
A newer request replaces the older link.

`POST <issuer>/account/api/me/email` with `{"email": "<new address>"}` asks to change the address the account signs in
with. It needs the recent sign-in described below (`401 reauthentication_required`) and a mail relay
(`503 mail_unavailable`); an address no account can sign in with is `400 email_rejected`, and the account's own address
answers `204` and sends nothing. Any other address answers `202` whether or not another account uses it. The change
takes effect a day after the request, once the new address confirms it and unless the current address cancels it
first (see [the server guide](server.md)). Past five requests in an hour the answer is `429` with `Retry-After`.

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
logged or recorded. A password seen in a breach is refused the same way (see [the server guide](server.md)).

## Your profile: `<issuer>/account/api/profile`

`POST <issuer>/account/api/profile` with `{"name": "...", "given_name": "...", "family_name": "..."}` replaces the
user's profile whole: each name is trimmed, at most 100 characters with no control character (otherwise
`400 profile_rejected` and nothing changes), and a name that is left out or empty is cleared. The answer and
`GET <issuer>/account/api/me` carry it as `profile`, each name `null` until set. UserInfo releases the names to a
token carrying `profile`, as they stand at that moment; they appear in no token.

## Your grants: `<issuer>/account/api/grants`

A signed-in user reads the grants they gave with `GET <issuer>/account/api/grants`: for each client still holding
one, the scopes, the resources and when it was given. `POST <issuer>/account/api/grants/revoke` with
`{"client_id": "<client>"}` ends that grant: the consent is withdrawn, which is recorded, and every refresh family
of that user at that client is revoked, so the client must ask again. The answer says how many families ended and
the time by which the access tokens it already holds stop working, at most five minutes on, because an access token
is never recalled. Both act for the session's own user and nobody else, need the session cookie (`401 session_required`
without it), take JSON only, are counted under their own limit and are never cached.

## Your sessions: `<issuer>/account/api/sessions`

`GET <issuer>/account/api/sessions` lists the signed-in user's live sessions at this issuer by their public id, with
when each signed in, when it was last used, the methods it signed in with, and which one is asking; never a cookie.
`POST <issuer>/account/api/sessions/end` with `{"sid": "<sid>"}` ends one of the user's own sessions (another
user's id ends nothing), and `POST <issuer>/account/api/sessions/end-all` with `{}` signs the user out everywhere:
every session, the asking one included, and every refresh family the user holds at any client. That answer says how
many of each ended and when the access tokens already issued stop working. Every ending is recorded in the audit
trail, and the same rules as the grant list apply: the session cookie, JSON only, their own limit, never cached.
