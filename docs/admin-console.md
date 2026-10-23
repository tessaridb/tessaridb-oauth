# Admin console

The admin console and its API at `<ADMIN_URL>/admin/<company>`, served on its own listener, and the audit trail.

## The admin console: `<ADMIN_URL>/admin/<company>`

An operator opens a company's console at `<ADMIN_URL>/admin/<company>/signin`, which sends the browser to that
company's own sign-in as the client `admin-console`, with PKCE, a `state` and a `nonce`. Every company has this client
registered, with no grant type, so nothing outside the server can redeem its codes. Each start points the client's
callback and resource at the `ADMIN_URL` and `PUBLIC_URL` the server runs with, so after a move operators consent
once more, to the new address. The consent page is always shown for this client, because what it grants is
administrative authority. The return to
`<ADMIN_URL>/admin/<company>/callback` opens a console session only when the `state`, the issuer, the code and its
`nonce` all check out, the operator signed in with two factors, and they hold at least one current operator role. Any
other return gets one and the same refusal and is recorded in the audit trail.

The session is kept in an `HttpOnly`, `SameSite=Strict` cookie (`__Host-` and `Secure` over https). It lasts at most
8 hours, ends after 30 minutes unused, and ends with the company sign-in session it came from or when the operator's
last role is taken away. `GET <ADMIN_URL>/admin/<company>/api/me` names the operator and their roles, and
`POST <ADMIN_URL>/admin/<company>/signout` ends the session, accepted only from the console's own origin. Console
requests are counted per client address under the `LOGIN_LIMIT` and `LOGIN_WINDOW_SECS` numbers.

The console itself is the page at `<ADMIN_URL>/admin/<company>/`, served by the binary with its script, style and mark
under `.../assets/`, for an active company only, under the same policy as the sign-in pages and never cached. It holds
no token, only the session cookie, and asks the API for everything it shows. It offers the sections the operator's roles
can use (Users, Groups, Clients, Operators, Sign-in policy, Branding, Mail, Signing keys, Audit trail, and Companies in
the `system` console); the API refuses the rest whatever is offered. Every change asks for a reason and is sent once
under its own `Idempotency-Key`.
Disabling an account names it and says what ends; removing a client says how many users hold a grant to it and asks for
its id typed out; deleting a group says how many members it has and asks for its id typed out; a two-factor policy
change or a company's suspension says what it does to every account and asks for the company's id typed out. Lists page
behind the server's cursor with no total, and an address is shown masked until it is revealed with a reason.

What the console does not do yet, stated as limits rather than promised: a change that reaches a whole company is
made by one operator (no second approval); the roles given by `bootstrap-operator` do not expire; and a company made
in the `system` console gets its first operator only through `bootstrap-operator --company`.

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

`POST <ADMIN_URL>/admin/<company>/api/users` (role `users`) with `{"email", "reason"}` opens an active account that
signs in with that address and answers `201` with its id and the address masked; an address the company already
has is refused as `email_taken`. The account has no password until its user enrols:
`POST .../api/users/<user>/enrolment` (role `users`, with a `reason`) answers `201` with an enrolment code valid for 72
hours, shown in that answer only and kept only as its digest; the same request sent again is answered without it, and
a new code replaces the earlier one. A code is refused for an account that already has a password
(`already_enrolled`: an enrolment never replaces a password) or is disabled (`account_disabled`).

Companies are made in the `system` console, by an operator holding `companies` (a role only `system` users can hold).
`GET <ADMIN_URL>/admin/system/api/companies` lists them, at most 100 a page; `POST` there with `{"id", "name",
"reason"}` creates a company, makes its database and its console's client, and serves its issuer at once (`201`); an
id already in use is refused as `company_taken`, except a company whose creation stopped before it was served, which
the same request completes. `POST .../api/companies/<id>/suspend` and `.../resume` (with a `reason`) stop and restart
serving a company's issuer on this node at once and on the others at their next directory refresh; each moves only
from the other status (`changed_meanwhile`), and `system` is never suspended (`system_company`).

`GET <ADMIN_URL>/admin/<company>/api/audit?after=<position>&limit=` (role `audit`) reads the company's audit trail in
order, at most 100 messages a page, `next` naming the position to read after; each message carries its `position`,
`at`, `kind` and only the fields it was written with.

Clients (role `clients`): `GET <ADMIN_URL>/admin/<company>/api/clients?limit=&after=` lists the company's client
registrations in id order (at most 100 a page, cursor = the last id) and `GET .../api/clients/<id>` reads one, each
with its kind, method, redirect URIs, scope ceiling, resources, grants and key count, and the one read also with
`holders`, how many users hold a grant to it; the console's own client is listed and marked.
`POST .../api/clients` with `{"client_id", "redirect_uris", "scope_ceiling", "resources",
"auth_method", "assertion_alg", "jwks", "grant_types", "dpop_bound_access_tokens", "post_logout_redirect_uris",
"backchannel_logout_uri", "reason"}` registers one through the same rules as every registration. Only `none` (a
public client, always with PKCE) and `private_key_jwt` (with `EdDSA` or `ES256` and its public key) are offered, so no
shared secret is ever made; `admin-console` is refused as `client_reserved` and a taken id as `client_taken`.
`POST .../api/clients/<id>/remove` with `{"reason"}` deletes the registration and ends what it held: every user's
grant to it is revoked as `client_removed` (it drops out of their grants list) and every refresh family it held is
revoked. The answer counts both and gives the time by which the access tokens it already holds stop working, at
most five minutes on. Sending it again finishes a removal that stopped part way; one that finds nothing to end is
`404 client_not_found`, and `admin-console` is `409 client_reserved`. Changing a client is not in the console yet.

Groups (role `users`): `GET <ADMIN_URL>/admin/<company>/api/groups?limit=&after=` lists the company's groups in id
order and `GET .../api/groups/<group>` reads one with the roles it carries; `GET .../api/groups/<group>/members`
lists its members (cursor = the last user id). `POST .../api/groups` with `{"group", "description", "roles",
"reason"}` makes one (`409 group_taken` for an id in use); a group id and a role are 1 to 64 lowercase letters,
digits, `-` and `_`. `POST .../groups/<group>/roles` with `{"roles", "reason"}` replaces its roles,
`POST .../groups/<group>/members` with `{"user", "reason"}` adds an account of the company (`404 user_not_found`,
`409 too_many_groups` past 100 groups for one account), `POST .../groups/<group>/members/<user>/remove` takes one out
and `POST .../groups/<group>/remove` deletes the group with every membership. A group holds accounts, never another
group; what its members are released as is described under UserInfo.

Operators: holding a role is what lets an operator give it. `GET <ADMIN_URL>/admin/<company>/api/operators` lists the
current grants of the roles the viewer holds (cursor `<user>.<role>`, at most 100 a page).
`POST .../api/operators/<user>/grants/<role>` with `{"reason", "valid_days"}` grants a role the operator holds to an
active account of the company for `valid_days` (90 unless given, at most 365; no grant made in the console is
permanent), recorded with who gave it; a grant to oneself is refused as `self_grant`. `POST
.../grants/<role>/revoke` with a `reason` takes it away (`not_granted` when it was not held), and the console of an
operator with no role left ends at their next request.

Branding (role `policy`): `GET <ADMIN_URL>/admin/<company>/api/branding` reads the company's `name`, `accent` colour,
`support_url`, `privacy_url`, when its `logo` was uploaded (Unix seconds), and the `revision` a change must name (0,
with every value null, while none is set). `PUT .../api/branding` with `{"revision", "name", "accent", "support_url",
"privacy_url", "reason"}` replaces the brand whole, only over the revision read (`409 changed_meanwhile` otherwise).
The name is 1 to 64 characters with no control or direction character (`brand_name_invalid`); the colour is `#` and
six hex digits (`accent_invalid`) on which white text reaches a contrast of 4.5 (`accent_low_contrast`); a link is an
https address with a host and no credentials (`link_invalid`). `PUT .../api/branding/logo` with `{"png", "reason"}`
takes a PNG as base64url, at most 256 KiB and 512 by 512 pixels (`logo_too_large`, `logo_not_png`,
`logo_unreadable`, `logo_too_wide`), and keeps only the server's own re-encoding of its pixels, so nothing else in
the file is ever served; `POST .../api/branding/logo/remove` takes it away (`404 no_logo`). The sign-in, consent and
account pages read `<issuer>/assets/brand.json` and `brand.css`: the name is set as text, the colour replaces the
house accent in the light theme, a link appears only when set, and the logo is `<issuer>/assets/logo.png`. With
nothing set they show TessariDB's own. Every brand asset comes from the issuer's origin, so the pages' policy is
unchanged.

Mail (role `policy`): `GET <ADMIN_URL>/admin/<company>/api/mail` lists the nine mails the server sends (`reset`,
`verify`, `email_confirm`, `email_taken`, `email_cancel`, `email_applied_old`, `email_applied_new`, `email_refused`,
`signin_changed`), each with the `subject` and `text` it goes out with, whether that wording is the company's `own`, the
`revision` a change must name (0 while the company keeps none), the `placeholders` it may carry and those it is
`required` to. `PUT .../api/mail/<kind>` with `{"revision", "subject", "text", "reason"}` keeps the company's own
wording, only over the revision read (`409 changed_meanwhile` otherwise). The wording is plain text: a subject of 1 to
200 characters on one line, a text of 1 to 10 000 characters with no control character but a line break, `{name}` for a
placeholder of that mail, `{{` and `}}` for a brace. A mail that works by its link must keep `{link}`, the cancellation
also names `{new_address}`, the notice to the old address names it too, and the sign-in notice keeps `{change}`;
anything else is refused as `400 template_rejected`, with the rule in the message. `POST .../api/mail/<kind>/reset` with
`{"revision", "reason"}` sends the default again (`404 not_found` when the company keeps none). The default is the
region's: a node writes the wording the server ships with at start for every mail the region has none for, and never
replaces one already kept. A stored wording that no longer passes its rules is skipped, and the shipped wording is used
when nothing else is. Who gets a mail, and when, stays the server's decision whatever the wording says. The trail
records each change with its reason, never the wording.

Signing keys (role `keys`): `GET <ADMIN_URL>/admin/<company>/api/keys` lists the company's keys oldest first, each with
its `kid`, `algorithm`, `created_at` and `state`: `signing`, `waiting` (published, signing from `signs_from`),
`previous` (still published for the tokens it signed), `retiring` (no longer published) or `withdrawn`; no private
part of a key is ever answered. `POST .../api/keys/rotate` with a `reason` makes a successor now, published at once
and signing five minutes later (`409 successor_waiting` while one already waits). `POST .../api/keys/<kid>/withdraw`
with a `reason` takes a key out of the key set at once, so every token it signed stops verifying, though a service
that cached the key set may accept them for up to five minutes; when no other key could sign, a new one is made
first and named as the `replacement` (`404 key_not_found` for a key the company does not have, `409
already_withdrawn`). A withdrawal revokes no refresh token. The console asks for the key's id typed out first.

`POST <ADMIN_URL>/admin/<company>/api/users/<user>/disable` and `.../enable` (role `users`) move an account between
`active` and `disabled`, each only from the other status (`changed_meanwhile` otherwise, `user_not_found` for an account
the company does not have). Disabling ends every session of the account, telling its clients through the back
channel, revokes every refresh family (recorded as `user_disabled`), and with the sessions ends any console session
of its own; its access tokens stop working by the `access_tokens_end_by` the answer gives. A disabled account cannot
sign in. Enabling gives back only that: nothing ended comes back.

## The audit trail

Every outcome at the token and revocation endpoints, and every refusal at the authorization and UserInfo endpoints,
is appended to an audit topic in the tenant's TessariDB database, which the store itself refuses to rewrite or delete
from, and kept for 400 days: what was issued — client, user, subject, scopes, audience, the access token's `jti`, the
authentication method and the bound key — what was refused and why, a replayed code, a reused refresh token and a
revocation. A message never carries a token, code, verifier, assertion or proof. An issuance that cannot be recorded
is not answered; a refusal is answered either way.
