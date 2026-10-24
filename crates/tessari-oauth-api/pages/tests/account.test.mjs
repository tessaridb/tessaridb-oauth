// The account page's decisions, without a browser: what the account API's answers mean, read as unknown and
// narrowed, so a field of another shape is refused rather than shown.
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  accountApi,
  changeRefusal,
  readEndBy,
  readGrants,
  readIssuedCodes,
  appAsked,
  enrolmentDue,
  profileRefused,
  readMe,
  readSavedNames,
  readSessions,
} from "../src/account-read.ts";

test("the account API lives under the page's tenant", () => {
  assert.equal(accountApi("/acme/account"), "/acme/account/api");
  assert.equal(accountApi("/a/b/account"), "/a/b/account/api");
  assert.equal(accountApi("/account"), null, "no tenant");
  assert.equal(accountApi("/acme/login"), null, "another page");
});

test("the account is read with its sign-in methods", () => {
  const me = readMe({
    email: "ada@example.com",
    email_verified: true,
    factors: {
      password: true,
      totp: false,
      recovery_codes: 3,
      passkeys: [{ id: "cred-1", created_at: 1700000000, synced: true }],
    },
    two_factor: "required",
    profile: { name: "Ada Lovelace", given_name: "Ada", family_name: null },
  });
  assert.deepEqual(me, {
    email: "ada@example.com",
    emailVerified: true,
    password: true,
    totp: false,
    recoveryCodes: 3,
    passkeys: [{ id: "cred-1", createdAt: 1700000000, synced: true }],
    twoFactor: "required",
    profile: { name: "Ada Lovelace", givenName: "Ada", familyName: null },
  });
  assert.equal(readMe({ email: "ada@example.com", email_verified: true }), null, "no factors");
  const factors = { password: true, totp: false, recovery_codes: 0, passkeys: [] };
  const base = { email: "ada@example.com", email_verified: true, factors, two_factor: "optional" };
  assert.equal(readMe(base), null, "no profile");
  assert.equal(readMe({ ...base, profile: { name: "Ada" } }), null, "a name left out rather than null");
  assert.equal(
    readMe({ ...base, profile: { name: 7, given_name: null, family_name: null } }),
    null,
    "a name of another type",
  );
  assert.equal(
    readMe({
      email: 7,
      email_verified: true,
      factors: { password: true, totp: false, recovery_codes: 0, passkeys: [] },
      two_factor: "optional",
    }),
    null,
    "an address of another type",
  );
  assert.equal(
    readMe({
      email: "ada@example.com",
      email_verified: true,
      factors: { password: true, totp: false, recovery_codes: -1, passkeys: [] },
      two_factor: "optional",
    }),
    null,
    "a negative count",
  );
  for (const policy of [undefined, "sometimes", "Off", 1]) {
    assert.equal(
      readMe({
        email: "ada@example.com",
        email_verified: true,
        factors: { password: true, totp: false, recovery_codes: 0, passkeys: [] },
        two_factor: policy,
      }),
      null,
      `a policy that is not one of the three: ${String(policy)}`,
    );
  }
  assert.equal(readMe(null), null);
});

test("sessions are read with the current one marked", () => {
  const sessions = readSessions({
    sessions: [
      { sid: "s1", signed_in_at: 10, last_seen_at: 20, methods: ["pwd", "otp"], current: true },
      { sid: "s2", signed_in_at: 5, last_seen_at: 6, methods: ["hwk"], current: false },
    ],
  });
  assert.deepEqual(sessions, [
    { sid: "s1", signedInAt: 10, lastSeenAt: 20, methods: ["pwd", "otp"], current: true },
    { sid: "s2", signedInAt: 5, lastSeenAt: 6, methods: ["hwk"], current: false },
  ]);
  assert.deepEqual(readSessions({ sessions: [] }), []);
  assert.equal(readSessions({ sessions: [{ sid: "s1" }] }), null, "a session missing its fields");
  assert.equal(
    readSessions({ sessions: [{ sid: "s1", signed_in_at: 1, last_seen_at: 2, methods: "pwd", current: true }] }),
    null,
    "methods that are not a list",
  );
  assert.equal(readSessions({}), null);
});

test("grants are read with what each holds", () => {
  const grants = readGrants({
    grants: [{ client_id: "portal", scopes: ["openid"], resources: ["https://api.example"], granted_at: 30 }],
  });
  assert.deepEqual(grants, [
    { clientId: "portal", scopes: ["openid"], resources: ["https://api.example"], grantedAt: 30 },
  ]);
  assert.equal(readGrants({ grants: [{ client_id: "portal", scopes: "openid", resources: [], granted_at: 1 }] }), null);
  assert.equal(readGrants(null), null);
});

test("an ending says when the issued access tokens stop working", () => {
  assert.equal(readEndBy({ revoked: true, families: 1, access_tokens_end_by: 1700000300 }), 1700000300);
  assert.equal(readEndBy({ sessions: 2, families: 0, access_tokens_end_by: 99 }), 99);
  assert.equal(readEndBy({ access_tokens_end_by: "soon" }), null);
  assert.equal(readEndBy({}), null);
});

test("new recovery codes are read only as a list of codes", () => {
  assert.deepEqual(
    readIssuedCodes({ codes: ["AAAA-BBBB", "CCCC-DDDD"], sessions: 1, families: 0, access_tokens_end_by: 9 }),
    ["AAAA-BBBB", "CCCC-DDDD"],
  );
  assert.equal(readIssuedCodes({ codes: [] }), null, "an empty set is not a set of codes");
  assert.equal(readIssuedCodes({ codes: ["AAAA", 7] }), null);
  assert.equal(readIssuedCodes({}), null);
});

test("a refused change names why in the page's words", () => {
  assert.equal(changeRefusal(401, { code: "reauthentication_required" }), "reauthenticate");
  assert.equal(changeRefusal(401, { code: "session_required" }), "signed-out");
  assert.equal(changeRefusal(400, { code: "password_rejected", message: "the password is too short" }), "too-short");
  assert.equal(
    changeRefusal(400, { code: "password_rejected", message: "the password is too easily guessed" }),
    "guessable",
  );
  assert.equal(changeRefusal(400, { code: "password_rejected", message: "something new" }), "rejected");
  assert.equal(changeRefusal(429, { code: "rate_limited" }), "other");
  assert.equal(changeRefusal(500, null), "other");
});

/** An account under `twoFactor` holding an app when `totp`, and `passkeys` passkeys. */
function held(twoFactor, totp, passkeys) {
  return {
    email: "ada@example.com",
    emailVerified: true,
    password: true,
    totp,
    recoveryCodes: 0,
    passkeys: Array.from({ length: passkeys }, (_, at) => ({ id: `cred-${at}`, createdAt: 0, synced: true })),
    twoFactor,
  };
}

test("an app counts only where the policy asks for its code", () => {
  assert.equal(appAsked(held("optional", true, 0)), true);
  assert.equal(appAsked(held("required", true, 0)), true);
  assert.equal(appAsked(held("off", true, 0)), false, "under off the app is never asked");
  assert.equal(appAsked(held("optional", false, 0)), false, "no app");
});

test("a required policy wants a second factor from an account holding none", () => {
  assert.equal(enrolmentDue(held("required", false, 0)), true);
  assert.equal(enrolmentDue(held("required", true, 0)), false, "an app");
  assert.equal(enrolmentDue(held("required", false, 1)), false, "a passkey");
  assert.equal(enrolmentDue(held("optional", false, 0)), false);
  assert.equal(enrolmentDue(held("off", false, 0)), false);
});

test("a saved profile is read back as the three names the account now keeps", () => {
  assert.deepEqual(readSavedNames({ profile: { name: null, given_name: "Ada", family_name: "Lovelace" } }), {
    name: null,
    givenName: "Ada",
    familyName: "Lovelace",
  });
  assert.equal(readSavedNames({ profile: { given_name: "Ada", family_name: "Lovelace" } }), null, "a name missing");
  assert.equal(readSavedNames({ name: "Ada", given_name: null, family_name: null }), null, "not under profile");
  assert.equal(readSavedNames(null), null);
});

test("only the profile rule's own refusal reads as a refused name", () => {
  assert.equal(profileRefused(400, { code: "profile_rejected", message: "a name must be at most 100 characters" }), true);
  assert.equal(profileRefused(400, { code: "invalid_request" }), false, "another 400");
  assert.equal(profileRefused(401, { code: "profile_rejected" }), false, "another status");
  assert.equal(profileRefused(400, null), false);
});
