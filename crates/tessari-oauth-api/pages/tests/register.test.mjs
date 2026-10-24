// The registration decisions on the sign-in page, without a browser: whether the company lets people open their own
// account, and where each answer to a request leaves the user. An accepted request answers alike for every address,
// so nothing here can tell whether an account exists.
import assert from "node:assert/strict";
import { test } from "node:test";

import { readOpen, registerOutcome } from "../src/register-read.ts";

test("registration is offered only when the server says it is open", () => {
  assert.equal(readOpen({ open: true }), true);
  assert.equal(readOpen({ open: false }), false);
  assert.equal(readOpen({ open: "true" }), false, "only a flag opens it");
  assert.equal(readOpen({}), false);
  assert.equal(readOpen(null), false);
});

test("every accepted address is sent the same way, and each refusal says what to do", () => {
  assert.deepEqual(registerOutcome(202, null, null), { kind: "sent" });
  assert.deepEqual(registerOutcome(503, { code: "mail_unavailable" }, null), { kind: "unavailable" });
  assert.deepEqual(registerOutcome(400, { code: "address_not_accepted" }, null), { kind: "domain" });
  assert.deepEqual(registerOutcome(400, { code: "email_rejected" }, null), { kind: "address" });
  assert.deepEqual(registerOutcome(404, { code: "not_found" }, null), { kind: "closed" });
  assert.deepEqual(registerOutcome(429, { code: "throttled" }, "60"), { kind: "throttled", seconds: 60 });
  assert.deepEqual(registerOutcome(500, { code: "internal" }, null), { kind: "retry" });
  assert.deepEqual(registerOutcome(400, { code: "invalid_request" }, null), { kind: "retry" });
});
