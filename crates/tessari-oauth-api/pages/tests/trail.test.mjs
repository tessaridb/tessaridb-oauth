// The sign-in policy and audit trail views' decisions, without a browser: the policy as the server names it, what a
// change does to the company's accounts, the typed confirmation, and the trail page with only the fields each
// message was written with.
import assert from "node:assert/strict";
import { test } from "node:test";

import { auditPath, readAuditPage } from "../src/audit-read.ts";
import { confirmedBy } from "../src/console-read.ts";
import { policyConsequence, readPolicy } from "../src/policy-read.ts";

test("the policy is read in its one spelling", () => {
  assert.equal(readPolicy({ policy: "required" }), "required");
  assert.equal(readPolicy({ policy: "optional" }), "optional");
  assert.equal(readPolicy({ policy: "off" }), "off");
  assert.equal(readPolicy({ policy: "Required" }), null);
  assert.equal(readPolicy({}), null);
});

test("a change says what it does to the company's accounts, and no change says nothing", () => {
  assert.equal(policyConsequence("optional", "optional"), null);
  const weaker = policyConsequence("required", "off");
  const stronger = policyConsequence("optional", "required");
  assert.ok(weaker !== null && stronger !== null);
  assert.notEqual(weaker, stronger);
  assert.match(stronger ?? "", /next sign-in/);
  assert.match(weaker ?? "", /password alone/);
});

test("a policy change is confirmed only by typing the company's id exactly", () => {
  assert.equal(confirmedBy(" acme ", "acme"), true);
  assert.equal(confirmedBy("Acme", "acme"), false);
  assert.equal(confirmedBy("", "acme"), false);
});

test("a trail page keeps each message's own fields, in a fixed order, and nothing it was not written with", () => {
  const page = readAuditPage({
    events: [
      { position: 7, at: 1761100000, kind: "token.issued", client_id: "app-1", scopes: ["openid", "email"], jti: "j1" },
      { position: 8, at: 1761100060, kind: "operator.change", actor: "user-1", role: "users", reason: "rota" },
    ],
    next: 8,
  });
  assert.deepEqual(page, {
    events: [
      {
        position: 7,
        at: 1761100000,
        kind: "token.issued",
        details: [
          ["Client", "app-1"],
          ["Scopes", "openid email"],
          ["Token id", "j1"],
        ],
      },
      {
        position: 8,
        at: 1761100060,
        kind: "operator.change",
        details: [
          ["Reason", "rota"],
          ["Operator", "user-1"],
          ["Role", "users"],
        ],
      },
    ],
    next: 8,
  });
});

test("a trail page with a field of the wrong shape is unreadable rather than shown in part", () => {
  assert.equal(readAuditPage({ events: [{ position: 1, at: 2, kind: "x", scopes: "openid" }], next: null }), null);
  assert.equal(readAuditPage({ events: [{ position: -1, at: 2, kind: "x" }], next: null }), null);
  assert.equal(readAuditPage({ events: [], next: "3" }), null);
  assert.deepEqual(readAuditPage({ events: [], next: null }), { events: [], next: null });
});

test("the trail follows its position cursor", () => {
  assert.equal(auditPath(null), "api/audit");
  assert.equal(auditPath(42), "api/audit?after=42");
});
