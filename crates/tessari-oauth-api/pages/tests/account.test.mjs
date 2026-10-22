// The account page's decisions, without a browser: what the account API's answers mean, read as unknown and
// narrowed, so a field of another shape is refused rather than shown.
import assert from "node:assert/strict";
import { test } from "node:test";

import { accountApi, readEndBy, readGrants, readMe, readSessions } from "../src/account-read.ts";

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
  });
  assert.deepEqual(me, {
    email: "ada@example.com",
    emailVerified: true,
    password: true,
    totp: false,
    recoveryCodes: 3,
    passkeys: [{ id: "cred-1", createdAt: 1700000000, synced: true }],
  });
  assert.equal(readMe({ email: "ada@example.com", email_verified: true }), null, "no factors");
  assert.equal(
    readMe({
      email: 7,
      email_verified: true,
      factors: { password: true, totp: false, recovery_codes: 0, passkeys: [] },
    }),
    null,
    "an address of another type",
  );
  assert.equal(
    readMe({
      email: "ada@example.com",
      email_verified: true,
      factors: { password: true, totp: false, recovery_codes: -1, passkeys: [] },
    }),
    null,
    "a negative count",
  );
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
