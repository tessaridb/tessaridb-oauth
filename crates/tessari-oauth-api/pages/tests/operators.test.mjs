// The operators view's decisions, without a browser: the grants page as the server answers it, the validity a form
// asks for, the cursor in the address, and what each refused grant or revocation tells the operator.
import assert from "node:assert/strict";
import { test } from "node:test";

import { route } from "../src/console-read.ts";
import { operatorRefusalText } from "../src/console-copy.ts";
import { daysOf, operatorsPath, readGrantsPage, readRevoked } from "../src/operators-read.ts";

const grant = {
  user: "user-4",
  role: "users",
  granted_by: "user-1",
  granted_at: 1761100000,
  expires_at: 1768876000,
  reason: "support rota",
};

test("a grants page is read with its cursor, and a grant of a role the console does not know is not", () => {
  assert.deepEqual(readGrantsPage({ operators: [grant], next: "user-4.users" }), {
    grants: [
      {
        user: "user-4",
        role: "users",
        grantedBy: "user-1",
        grantedAt: 1761100000,
        expiresAt: 1768876000,
        reason: "support rota",
      },
    ],
    next: "user-4.users",
  });
  assert.equal(readGrantsPage({ operators: [{ ...grant, role: "root" }], next: null }), null);
  assert.equal(readGrantsPage({ operators: [{ ...grant, granted_at: "soon" }], next: null }), null);
  assert.equal(readGrantsPage({ next: null }), null);
});

test("a grant with no expiry is read as never expiring", () => {
  const page = readGrantsPage({ operators: [{ ...grant, expires_at: null }], next: null });
  assert.equal(page?.grants[0]?.expiresAt, null);
  assert.equal(page?.next, null);
});

test("a revocation is read only when it says it revoked", () => {
  assert.deepEqual(readRevoked({ user: "user-4", role: "users", revoked: true }), { user: "user-4", role: "users" });
  assert.equal(readRevoked({ user: "user-4", role: "users", revoked: false }), null);
});

test("a grant lasts 1 to 365 whole days, and an empty field asks for the default 90", () => {
  assert.equal(daysOf(""), 90);
  assert.equal(daysOf(" 30 "), 30);
  assert.equal(daysOf("1"), 1);
  assert.equal(daysOf("365"), 365);
  assert.equal(daysOf("0"), null);
  assert.equal(daysOf("366"), null);
  assert.equal(daysOf("7.5"), null);
  assert.equal(daysOf("1e2"), null);
});

test("the grants page follows the cursor in the address", () => {
  assert.equal(operatorsPath(null), "api/operators");
  assert.equal(operatorsPath("user-4.users"), "api/operators?after=user-4.users");
  assert.deepEqual(route("#/operators?after=user-4.users"), { kind: "operators", after: "user-4.users" });
  assert.deepEqual(route("#/operators"), { kind: "operators", after: null });
});

test("each refused grant or revocation says what happened in words, not its code", () => {
  for (const code of ["self_grant", "above_ceiling", "account_disabled", "not_granted"]) {
    const text = operatorRefusalText(code);
    assert.notEqual(text, operatorRefusalText("something-else"), code);
    assert.ok(!text.includes(code), `${code} is said in words`);
  }
  assert.match(operatorRefusalText("account_disabled"), /grant/, "a grant's own wording, not the enrolment one");
  assert.equal(operatorRefusalText("reason_required"), "Say why, in 1 to 500 characters.");
});

test("one form changing two records sends them under two keys", async () => {
  const { change, keys } = await import("../src/console-change.ts");
  const sent = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (path, init) => {
    sent.push({ path, key: new Headers(init.headers).get("idempotency-key") });
    return new Response("{}", { status: 200 });
  };
  try {
    const keyFor = keys();
    await change("api/operators/user-4/grants/users/revoke", keyFor, { reason: "left the team" });
    await change("api/operators/user-5/grants/users/revoke", keyFor, { reason: "left the team" });
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(sent.length, 2);
  assert.notEqual(sent[0].key, sent[1].key, "another record is another change");
  assert.match(sent[0].key ?? "", /^[0-9a-f-]{36}$/);
});
