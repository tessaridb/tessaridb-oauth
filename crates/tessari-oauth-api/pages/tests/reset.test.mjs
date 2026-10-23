// The password-reset decisions, without a browser: where the API is for the reset page, which link fragments carry
// a token, and where each answer to a reset request or a new password leaves the user.
import assert from "node:assert/strict";
import { test } from "node:test";

import { readResetToken, requestOutcome, completeOutcome, resetApi } from "../src/reset-read.ts";

const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";

test("the reset page's API is the sign-in API of its tenant", () => {
  assert.equal(resetApi("/acme/login/reset"), "/acme/login/api");
  assert.equal(resetApi("/a/b/login/reset"), "/a/b/login/api");
  assert.equal(resetApi("/login/reset"), null, "no tenant");
  assert.equal(resetApi("/acme/login"), null, "another page");
  assert.equal(resetApi("/acme/reset"), null, "not under the sign-in page");
});

test("only a link fragment carrying one well-formed token is read", () => {
  assert.equal(TOKEN.length, 43);
  assert.equal(readResetToken(`#token=${TOKEN}`), TOKEN);
  assert.equal(readResetToken(""), null);
  assert.equal(readResetToken("#"), null);
  assert.equal(readResetToken("#token="), null);
  assert.equal(readResetToken(`#token=${TOKEN.slice(1)}`), null, "too short");
  assert.equal(readResetToken(`#token=${TOKEN}A`), null, "too long");
  assert.equal(readResetToken(`#token=${TOKEN.slice(1)}+`), null, "not base64url");
  assert.equal(readResetToken(`#other=${TOKEN}`), null);
  assert.equal(readResetToken(`#token=${TOKEN}&token=${TOKEN}`), null, "one token, nothing else");
});

test("a reset request answers alike for every address", () => {
  assert.deepEqual(requestOutcome(202, null, null), { kind: "sent" });
  assert.deepEqual(requestOutcome(503, { code: "mail_unavailable" }, null), { kind: "unavailable" });
  assert.deepEqual(requestOutcome(429, { code: "rate_limited" }, "12"), { kind: "throttled", seconds: 12 });
  assert.deepEqual(requestOutcome(503, { code: "store_unavailable" }, null), { kind: "retry" });
  assert.deepEqual(requestOutcome(200, null, null), { kind: "retry" }, "only 202 means sent");
});

test("a new password lands, is refused by its rules, or finds the link spent", () => {
  assert.deepEqual(completeOutcome(204, null, null), { kind: "changed" });
  assert.deepEqual(completeOutcome(400, { code: "code_rejected" }, null), { kind: "link" });
  assert.deepEqual(
    completeOutcome(400, { code: "password_rejected", message: "the password is too short" }, null),
    { kind: "password", why: "too-short" },
  );
  assert.deepEqual(
    completeOutcome(400, { code: "password_rejected", message: "something new" }, null),
    { kind: "password", why: "rejected" },
  );
  assert.deepEqual(completeOutcome(429, { code: "rate_limited" }, null), { kind: "throttled", seconds: null });
  assert.deepEqual(completeOutcome(500, null, null), { kind: "retry" });
  assert.deepEqual(completeOutcome(200, null, null), { kind: "retry" }, "only 204 means changed");
});
