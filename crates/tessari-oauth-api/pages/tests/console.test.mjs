// The admin console's shell decisions, without a browser: who the console is signed in as, which sections the roles
// it holds can use, and which view a hash names. Every answer is read as unknown and narrowed.
import assert from "node:assert/strict";
import { test } from "node:test";

import { offered, readMe, route } from "../src/console-read.ts";

test("the signed-in operator is read with the roles the console knows", () => {
  const both = { user: "user-7", roles: ["users", "audit"] };
  assert.deepEqual(readMe(both), both);
  assert.deepEqual(readMe({ user: "user-7", roles: ["audit", "someday"] }), { user: "user-7", roles: ["audit"] });
  assert.equal(readMe({ user: 7, roles: [] }), null, "an id of another shape");
  assert.equal(readMe({ user: "user-7" }), null, "no roles");
  assert.equal(readMe({ user: "", roles: [] }), null, "an empty id");
  assert.equal(readMe(null), null);
});

test("a section is offered only to the roles that can use it", () => {
  assert.deepEqual(offered(["audit"]), ["operators", "audit"]);
  assert.deepEqual(offered(["users", "policy"]), ["users", "operators", "policy"]);
  assert.deepEqual(offered(["companies"]), ["operators", "companies"]);
  assert.deepEqual(offered([]), ["operators"]);
});

test("a hash names one view, and anything else is the overview", () => {
  assert.deepEqual(route(""), { kind: "overview" });
  assert.deepEqual(route("#/"), { kind: "overview" });
  assert.deepEqual(route("#/users"), { kind: "users", email: null, after: null });
  assert.deepEqual(route("#/users?email=ada%40example.com"), { kind: "users", email: "ada@example.com", after: null });
  assert.deepEqual(route("#/users?after=user-9"), { kind: "users", email: null, after: "user-9" });
  assert.deepEqual(route("#/users/user-9"), { kind: "user", id: "user-9" });
  assert.deepEqual(route("#/operators"), { kind: "operators", after: null });
  assert.deepEqual(route("#/policy"), { kind: "policy" });
  assert.deepEqual(route("#/audit"), { kind: "audit", after: null });
  assert.deepEqual(route("#/audit?after=40"), { kind: "audit", after: 40 });
  assert.deepEqual(route("#/audit?after=x"), { kind: "audit", after: null }, "a position is a whole number");
  assert.deepEqual(route("#/companies"), { kind: "companies" });
  assert.deepEqual(route("#/elsewhere"), { kind: "overview" });
  assert.deepEqual(route("#/users/"), { kind: "users", email: null, after: null });
});
