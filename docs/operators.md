# Platform operators

The emergency path for the first operator, and operator roles.


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
