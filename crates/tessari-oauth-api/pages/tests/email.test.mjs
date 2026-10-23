// The address-change decisions, without a browser: where the API is for the page the change mails open, which
// fragments carry a link, and where each answer leaves the user, on that page and on the account page.
import assert from "node:assert/strict";
import { test } from "node:test";

import { askOutcome, cancelOutcome, confirmOutcome, emailApi, readEmailLink } from "../src/email-read.ts";

const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";

test("the address-change page's API is the sign-in API of its tenant", () => {
  assert.equal(emailApi("/acme/login/email"), "/acme/login/api");
  assert.equal(emailApi("/a/b/login/email"), "/a/b/login/api");
  assert.equal(emailApi("/login/email"), null, "no tenant");
  assert.equal(emailApi("/acme/login/verify"), null, "another page");
});

test("a fragment carries one confirm or one cancel link, and nothing else", () => {
  assert.deepEqual(readEmailLink(`#confirm=${TOKEN}`), { kind: "confirm", token: TOKEN });
  assert.deepEqual(readEmailLink(`#cancel=${TOKEN}`), { kind: "cancel", token: TOKEN });
  assert.equal(readEmailLink(`#token=${TOKEN}`), null, "a verification link is not one");
  assert.equal(readEmailLink(`#confirm=${TOKEN.slice(1)}`), null, "too short");
  assert.equal(readEmailLink(`#cancel=${TOKEN}A`), null, "too long");
  assert.equal(readEmailLink(`#confirm=${TOKEN}&cancel=${TOKEN}`), null, "one link only");
  assert.equal(readEmailLink(""), null);
});

test("confirming says when the change takes effect, and a spent link says so", () => {
  assert.deepEqual(confirmOutcome(202, { effective_at: 1800086400 }, null), {
    kind: "confirmed",
    effectiveAt: 1800086400,
  });
  assert.deepEqual(confirmOutcome(202, {}, null), { kind: "retry" }, "an answer without the time is not read");
  assert.deepEqual(confirmOutcome(400, { code: "code_rejected" }, null), { kind: "link" });
  assert.deepEqual(confirmOutcome(429, { code: "rate_limited" }, "5"), { kind: "throttled", seconds: 5 });
  assert.deepEqual(confirmOutcome(204, null, null), { kind: "retry" }, "only 202 means confirmed");
});

test("cancelling ends the change once, and a spent link says so", () => {
  assert.deepEqual(cancelOutcome(204, null, null), { kind: "cancelled" });
  assert.deepEqual(cancelOutcome(400, { code: "code_rejected" }, null), { kind: "link" });
  assert.deepEqual(cancelOutcome(429, { code: "rate_limited" }, null), { kind: "throttled", seconds: null });
  assert.deepEqual(cancelOutcome(202, null, null), { kind: "retry" }, "only 204 means cancelled");
});

test("asking for a change from the account page", () => {
  assert.deepEqual(askOutcome(202, null, null), { kind: "sent" });
  assert.deepEqual(askOutcome(204, null, null), { kind: "same" });
  assert.deepEqual(askOutcome(400, { code: "email_rejected" }, null), { kind: "invalid" });
  assert.deepEqual(askOutcome(401, { code: "reauthentication_required" }, null), { kind: "reauthenticate" });
  assert.deepEqual(askOutcome(401, { code: "session_required" }, null), { kind: "signed-out" });
  assert.deepEqual(askOutcome(503, { code: "mail_unavailable" }, null), { kind: "unavailable" });
  assert.deepEqual(askOutcome(503, { code: "unavailable" }, null), { kind: "retry" });
  assert.deepEqual(askOutcome(200, null, null), { kind: "retry" }, "only 202 means sent");
});
