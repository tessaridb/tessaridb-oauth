# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-24

The first release. It needs TessariDB 0.38.2 or later.

### Added

- Authorization server and OpenID provider with one issuer per company: discovery and key set, authorization with
  PKCE `S256` and pushed authorization requests, the token endpoint for authorization codes, refresh tokens and
  client credentials, revocation, UserInfo, RP-initiated and back-channel logout.
- Clients authenticate with `private_key_jwt` (`EdDSA` or `ES256`) or are public; there are no shared secrets.
- Codes redeem once under concurrency; a replayed code or a reused refresh token revokes the refresh family.
- DPoP-bound tokens, including codes bound to a key by `dpop_jkt` or by the proof at the pushed request.
- Five-minute access tokens addressed to one resource, ID tokens with `acr` and `amr` from the methods verified,
  pairwise subjects, and UserInfo releasing names under `profile` and groups and roles under `groups`.
- Sign-in with passwords, authenticator apps, recovery codes and passkeys; holds that end by themselves instead of
  lockouts; new passwords screened against a breached-password range service.
- Password reset, enrolment links, address verification, changes of sign-in address and sign-in notices by mail,
  worded per company; self-registration under company policy.
- The account portal: profile, sign-in factors, sessions and the applications that hold access.
- The admin console on its own listener: companies, users, groups, clients, operators, sign-in policy, branding,
  mail wording, signing-key rotation and withdrawal, and the audit trail.
- The audit trail on a TessariDB topic kept for 400 days; regions with home-region redirects; per-address request
  limits counted in TessariDB; `bootstrap-operator` and `reseal` for operators.
- A container image, `tessaridb/oauth`, for `linux/amd64` and `linux/arm64`.
