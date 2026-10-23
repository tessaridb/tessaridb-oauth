# Platform operators

The emergency path for the first operator, operator roles, and what to do in an incident: an exposed signing key,
a leaked client credential, a taken account.


```sh
tessaridb-oauth bootstrap-operator --email root@example.com
tessaridb-oauth bootstrap-operator --company acme --email ops@acme.example
```

This is the emergency path, for the first operator after installation or for one whose access is lost. It reads
the same environment as the server and needs only the store. It creates and activates the `system` company when
there is none, finds or registers the account with that address there, and gives it the operator roles `companies`
and `users`. When the account has no password yet it prints a one-time enrolment code for
`POST <PUBLIC_URL>/system/login/api/enroll`; an account that has a password keeps it. The code is shown once and
never logged, so run the command at a terminal rather than under a supervisor that collects its output. Every run
is logged at `ERROR` as `break_glass` and recorded on the `system` company's audit trail.

With `--company`, the same path gives a company made since its first operator: the company must exist and be served
(an unknown, provisioning or suspended one is refused and nothing is written), the account is found or registered in
that company, it is given `users`, `clients`, `policy`, `keys` and `audit` there (never `companies`), the code is for
`POST <PUBLIC_URL>/<company>/login/api/enroll`, and the run is recorded on that company's audit trail.

Operator roles are held per company and per task: `users`, `clients`, `policy`, `keys`, `audit`, and `companies`,
which only users of the `system` company may hold. A grant names who gave it and why, may carry an expiry after which
it no longer counts, and is refused when it names its own holder as the giver. Every grant and revoke is on the
company's audit trail.

## A signing key that may be exposed

When a company's private signing key may have been read by someone else (a leaked backup, a host compromise, a
departing operator who could reach the key-encryption key), withdraw it at once; there is no reason to wait:

1. Find the key: `GET <ADMIN_URL>/admin/<company>/api/keys` lists each key with its `kid` and `state`; the one to
   withdraw is usually the `signing` one.
2. Withdraw it with an operator holding `keys`: `POST <ADMIN_URL>/admin/<company>/api/keys/<kid>/withdraw` with a
   `reason`. The answer names the key `withdrawn` and the `replacement`, if one had to be made. When no other key
   could sign, the replacement is made before the withdrawal and signs at once; otherwise a key already published
   takes over. The withdrawn key leaves the key set in the same request, and the console then shows it `withdrawn`.
3. Expect what the key signed to stop verifying. A service that fetches the key set again refuses those tokens at
   once; one that cached it may accept them for up to five minutes, the cache lifetime the key set is served with,
   which is also how long an access token or ID token lives. A token forged with the exposed key is bounded the same
   way. Refresh tokens are random values the server holds only as digests, not signed, so they stay valid and need
   no revocation for a key exposure.
4. Tell the company's integrators which `kid` was withdrawn and when, so a service that pins keys or caches them
   longer than five minutes can drop it.
5. Check the company's audit trail for the `keys.withdraw` entry and for anything else done with the same access.

Every key of every company is sealed with the server's key-encryption key (`TESSARIDB_OAUTH_KEK`). If that file
itself may be exposed, withdrawing keys is not enough, because a replacement is sealed with the same file; this
version has no command that re-seals the keys under a new key-encryption key.

## A leaked client credential

When a client's private key (or the host that holds it) may be in someone else's hands, remove the client with an
operator holding `clients`: `POST <ADMIN_URL>/admin/<company>/api/clients/<id>/remove` with a `reason`. The key stops
authenticating at once, every user's grant to the client and every refresh family it held are revoked, and the answer
gives `access_tokens_end_by`, at most five minutes on, after which the access tokens it already holds stop working.
Then register the client again with a new key; it may keep its `client_id`, and it starts with nothing: no grant and
no refresh token from before comes back, so every user is asked again.

## A taken account

When an account may be used by someone other than its owner, disable it with an operator holding `users`:
`POST <ADMIN_URL>/admin/<company>/api/users/<user>/disable` with a `reason`. Every session of the account ends at once
(its clients are told through the back channel), every refresh family is revoked, nobody can sign in to it, and its
access tokens stop working by the `access_tokens_end_by` the answer gives. Once the owner is reached, enable it again
(`POST .../users/<user>/enable`, which gives back none of what was ended) and have the owner ask for a password reset
from the sign-in page; the reset keeps the account's second factor.
