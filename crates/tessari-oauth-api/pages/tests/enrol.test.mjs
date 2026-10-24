// The enrolment-link decisions, without a browser: where the API is for the enrolment page, which link fragments
// carry a code, and where each answer to a first password leaves the user.
import assert from "node:assert/strict";
import { test } from "node:test";

import { enrolApi, enrolOutcome, readEnrolCode } from "../src/enrol-read.ts";

const CODE = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

test("the enrolment page's API is the sign-in API of its tenant", () => {
  assert.equal(enrolApi("/acme/login/enrol"), "/acme/login/api");
  assert.equal(enrolApi("/a/b/login/enrol"), "/a/b/login/api");
  assert.equal(enrolApi("/login/enrol"), null, "no tenant");
  assert.equal(enrolApi("/acme/login/reset"), null, "another page");
  assert.equal(enrolApi("/acme/enrol"), null, "not under the sign-in page");
});

test("only a link fragment carrying one well-formed code is read", () => {
  assert.equal(CODE.length, 43);
  assert.equal(readEnrolCode(`#code=${CODE}`), CODE);
  assert.equal(readEnrolCode(""), null);
  assert.equal(readEnrolCode("#code="), null);
  assert.equal(readEnrolCode(`#code=${CODE.slice(1)}`), null, "too short");
  assert.equal(readEnrolCode(`#code=${CODE}A`), null, "too long");
  assert.equal(readEnrolCode(`#code=${CODE.slice(1)}+`), null, "not base64url");
  assert.equal(readEnrolCode(`#token=${CODE}`), null, "a reset link is not an enrolment link");
  assert.equal(readEnrolCode(`#code=${CODE}&code=${CODE}`), null, "one code, nothing else");
});

test("a first password lands, is refused by its rules, or finds the link spent or the account set", () => {
  assert.deepEqual(enrolOutcome(204, null, null), { kind: "set" });
  assert.deepEqual(enrolOutcome(400, { code: "code_rejected" }, null), { kind: "link" });
  assert.deepEqual(enrolOutcome(409, { code: "already_enrolled" }, null), { kind: "already" });
  assert.deepEqual(
    enrolOutcome(400, { code: "password_rejected", message: "the password is too short" }, null),
    { kind: "password", why: "too-short" },
  );
  assert.deepEqual(enrolOutcome(429, { code: "rate_limited" }, "7"), { kind: "throttled", seconds: 7 });
  assert.deepEqual(enrolOutcome(409, { code: "nothing_pending" }, null), { kind: "retry" }, "only already_enrolled");
  assert.deepEqual(enrolOutcome(500, null, null), { kind: "retry" });
  assert.deepEqual(enrolOutcome(200, null, null), { kind: "retry" }, "only 204 means set");
});
