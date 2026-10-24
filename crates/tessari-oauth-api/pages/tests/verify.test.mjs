// The address-verification decisions, without a browser: where the API is for the page a verification link opens,
// which fragments carry a token, and where each answer leaves the user, on that page and on the account page.
import assert from "node:assert/strict";
import { test } from "node:test";

import { readVerifyToken, sendOutcome, verifyApi, verifyOutcome } from "../src/verify-read.ts";

const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";

test("the verification page's API is the sign-in API of its tenant", () => {
  assert.equal(verifyApi("/acme/login/verify"), "/acme/login/api");
  assert.equal(verifyApi("/a/b/login/verify"), "/a/b/login/api");
  assert.equal(verifyApi("/login/verify"), null, "no tenant");
  assert.equal(verifyApi("/acme/login/reset"), null, "another page");
  assert.equal(verifyApi("/acme/verify"), null, "not under the sign-in page");
});

test("only a link fragment carrying one well-formed token is read", () => {
  assert.equal(readVerifyToken(`#token=${TOKEN}`), TOKEN);
  assert.equal(readVerifyToken(""), null);
  assert.equal(readVerifyToken("#token="), null);
  assert.equal(readVerifyToken(`#token=${TOKEN.slice(1)}`), null, "too short");
  assert.equal(readVerifyToken(`#token=${TOKEN}A`), null, "too long");
  assert.equal(readVerifyToken(`#token=${TOKEN}&x=1`), null, "one token, nothing else");
});

test("opening a link verifies the address once, and a spent link says so", () => {
  assert.deepEqual(verifyOutcome(204, null, null), { kind: "verified" });
  assert.deepEqual(verifyOutcome(400, { code: "code_rejected" }, null), { kind: "link" });
  assert.deepEqual(verifyOutcome(429, { code: "rate_limited" }, "7"), { kind: "throttled", seconds: 7 });
  assert.deepEqual(verifyOutcome(400, { code: "invalid_request" }, null), { kind: "retry" });
  assert.deepEqual(verifyOutcome(200, null, null), { kind: "retry" }, "only 204 means verified");
});

test("asking for a link sends one, finds the address verified, or finds mail not set up", () => {
  assert.deepEqual(sendOutcome(202, null, null), { kind: "sent" });
  assert.deepEqual(sendOutcome(204, null, null), { kind: "verified" });
  assert.deepEqual(sendOutcome(503, { code: "mail_unavailable" }, null), { kind: "unavailable" });
  assert.deepEqual(sendOutcome(401, { code: "session_required" }, null), { kind: "signed-out" });
  assert.deepEqual(sendOutcome(429, { code: "rate_limited" }, null), { kind: "throttled", seconds: null });
  assert.deepEqual(sendOutcome(503, { code: "store_unavailable" }, null), { kind: "retry" });
  assert.deepEqual(sendOutcome(200, null, null), { kind: "retry" }, "only 202 means sent");
});
