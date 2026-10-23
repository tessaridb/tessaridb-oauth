# How the server runs

What the server does at start and while it serves, the pages it carries, and how it stops.

At start the server records each configured company in the region's directory, provisions its database, registers
its admin console as the client `admin-console` of the company's issuer (redirected only to the console's own
callback, asking for nothing past `openid`, addressed to `<PUBLIC_URL>/<company>/admin`, and with no grant the token
endpoint will redeem) and makes it
active, makes a signing key for any company without one and then checks every five minutes for keys due to rotate.
Every node re-reads which companies are active every five seconds and serves exactly those: a company that is not
active answers `404`, like a name that was never a company.
Each read, authorization request, token request and sign-in step is
counted per client address in TessariDB (the connection's peer, or behind a proxy listed in `TRUSTED_PROXIES` the
right-most `X-Forwarded-For` address that is not a listed proxy), under separate limits; past the limit the answer
is `429` with
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

The sign-in, password-reset, enrolment, address-verification, address-change, consent and account pages are served by
the binary itself at `<issuer>/login`, `<issuer>/login/reset`, `<issuer>/login/enrol`, `<issuer>/login/verify`,
`<issuer>/login/email`, `<issuer>/consent` and `<issuer>/account`, with their script, style and mark under
`<issuer>/assets/`. The account page shows the signed-in user's address, offers a link that verifies it and a change
to another one, how the account signs in, where it is signed in and which applications hold access; it
signs out one session or every session after a confirmation, takes an application's access back, saying when the
tokens it already holds stop working, changes the password, issues new recovery codes shown once, turns on an
authenticator app from a key shown once, and adds or removes passkeys. Without a session it offers a sign-in
(`<issuer>/login?return=account`) that comes back to it, and it offers the same sign-in when a change needs a recent
one. They load nothing from anywhere else, talk only to this server, submit no form, cannot be framed, follow the
system's light or dark theme and work from the keyboard alone; a passkey is offered wherever the browser supports
one. Their TypeScript source is in `crates/tessari-oauth-api/pages/`, and its built output is committed to
`crates/tessari-oauth-api/assets/`, so building the server needs no Node. After changing the source, `npm install`
once and `npm run build` there; `npm run verify` type-checks, runs the page tests and fails when the committed
assets differ from a rebuild.

With `SMTP_URL` set the server sends mail through that relay: a password-reset link, an enrolment link an operator
sends or a registration asks for, a notice to an address that asked to open an account it already has,
and a notice to the account's address when its sign-in changes (password changed or reset, a passkey or
authenticator app added or removed, new
recovery codes, a recovery code used, every session signed out). A notice carries no link. A request only writes the
mail, sealed under the KEK, to a queue in the company's database; a background task sends what is due every five
seconds, each send bounded to 20 seconds, tries a mail the relay did not take again after 30 seconds and then twice
as long each time, and drops it after its sixth try. No address, subject or text is logged. Each mail goes out with
the company's own wording when its console keeps one, and with the region's default otherwise (see
[the admin console](admin-console.md)).

A user who forgot the password asks from the sign-in page. `POST <issuer>/login/api/reset` with an address answers
`202` for every address, with or without an account, and does the same store work for each, so the answer says
nothing about who has an account; without a relay it answers `503` with `mail_unavailable` for every address. An
address with an account gets a link to `<issuer>/login/reset#token=<token>`. It works once, for 30 minutes, and stops
working when a newer link is asked for or the account signs in. The token travels in the fragment, which reaches
neither the server's logs nor a `Referer`, and the page takes it out of the address before it sends anything. Setting
the new password (`POST <issuer>/login/api/reset/complete`) changes the password only: the authenticator app and
passkeys stay, so the next sign-in still asks for them. Every session ends, every refresh token is revoked, the
change is recorded and a notice goes to the address. A link that was never issued, was used, was replaced or has
lapsed gets `400` `code_rejected`.

An operator can send a new account its enrolment code by mail instead of handing it over. The link opens
`<issuer>/login/enrol#code=<code>`, a page that takes the code out of the address the same way and sets the account's
first password (`POST <issuer>/login/api/enroll`), at least 15 characters. The code is spent only when a password is
accepted, so a refused one can be tried again; an unknown, used or replaced code gets `400` `code_rejected` before the
password is looked at, and an account that already has a password gets `409` `already_enrolled` and keeps it.

A company can let people open their own account. It is closed until an operator opens it in the console, and
`GET <issuer>/login/api/registration` answers `{"open": true}` or `{"open": false}` and nothing more. While it is
open, the sign-in page offers "Create an account", which sends `POST <issuer>/login/api/register` with the typed
address. A closed company answers `404`, a server with no relay `503` `mail_unavailable`, an address that cannot be
one `400` `email_rejected`, and an address at a domain the company does not list `400` `address_not_accepted`.
Every other address gets `202` and the same body, and the mailbox learns the rest: an address with no account gets
a new account and an enrolment link, an account that never set a password gets a new link that replaces the old one,
an account that signs in gets a notice and no link, and a disabled account gets nothing. The requester is never told
that an address is taken. Each address may be asked for 3 times an hour and each client address 10 times, whatever
the addresses. Opening an account sets no password and opens no session, and the address stays unverified until its
own link is opened.

An account's address stays unverified (`email_verified` is false) until a link sent to it is opened. With a relay
set, a link to `<issuer>/login/verify#token=<token>` is mailed when an account sets its first password and whenever
the signed-in user asks for one on the account page. It works once, for 24 hours, and a newer link replaces it. The
page takes the token out of the address and posts it to `POST <issuer>/login/api/verify`, which marks the address
verified and records it (`204`). A link that was never issued, was used, was replaced, has lapsed or was sent to an
address the account no longer signs in with gets `400` `code_rejected`.

The signed-in user changes the address the account signs in with from the account page, which needs a sign-in from the
last ten minutes. The new address gets a link to `<issuer>/login/email#confirm=<token>` that works for 24 hours, and the
current address gets one to `<issuer>/login/email#cancel=<token>` that names the new address. The change waits a day
from the request even when it is confirmed at once, so the current address can still cancel it. Every minute a task
applies the confirmed changes that are due, each in one transaction: the new address then signs in, already verified,
the old one is free, and both get a notice. When another account has taken the new address in the meantime, the change
is dropped and the current address is told it still signs in. An address another account already signs in with gets
the same `202` as a free one and a notice with no link, so asking says nothing about who has an account. An account
may ask five times an hour. The page posts a confirmation at once (`POST <issuer>/login/api/email/confirm`, `202` with
`effective_at`), but a cancellation only when the user presses its button (`POST <issuer>/login/api/email/cancel`,
`204`), so a mail filter that opens links cannot cancel a change. A link that was never issued, was used, was replaced,
has lapsed or whose change already took effect gets `400` `code_rejected`.

Logs are JSON on standard output, filtered by
`RUST_LOG` (`info` by default). On `SIGINT` or `SIGTERM` the listeners stop accepting, the requests in flight
finish within 25 seconds, and the process exits 0.

A line about something that happened carries an `event` field; these are the ones worth an alert. At `ERROR`:
`break_glass` (the emergency operator path ran) and `audit_unrecorded` (an event could not be appended to the audit
trail; an issuance it belonged to was not answered). At `WARN`, worth an alert on any occurrence: `code_replayed` (a
redeemed code presented again; the refresh family it started is revoked), `refresh_reused` (a rotated refresh token
presented again; its family is revoked), `passkey_clone_suspected` (a passkey's counter did not move forward) and
`recovery_code_used`. At `WARN`, worth an alert on a rise above the usual rate: `signin_rejected` (a rejected
sign-in credential), `authorization_refused`, `userinfo_refused` (its `reason` `AccessTokenUnverified` covers a
token whose signature, key or algorithm is not the issuer's), `logout_untold` and `mail_abandoned`. The server sends
no alerts itself.
