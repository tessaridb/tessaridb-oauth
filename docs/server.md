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
