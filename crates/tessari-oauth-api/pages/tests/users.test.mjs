// The users views' decisions, without a browser: what to ask the users API for a route, what its answers mean, and
// what a refusal leaves the operator to do. Every answer is read as unknown and narrowed.
import assert from "node:assert/strict";
import { test } from "node:test";

import { readRefusal } from "../src/console-read.ts";
import { readUser, readUsersPage, usersPath } from "../src/users-read.ts";

const ADA = { user: "user-1", email: "a***@example.com", email_verified: true, status: "active" };

test("a route asks for one exact address, a page after an account, or the first page", () => {
  assert.equal(usersPath({ email: "ada@example.com", after: null }), "api/users?email=ada%40example.com");
  assert.equal(usersPath({ email: null, after: "user-9" }), "api/users?after=user-9");
  assert.equal(usersPath({ email: null, after: null }), "api/users");
  assert.equal(usersPath({ email: "  ", after: null }), "api/users", "a blank address is no lookup");
});

test("an account is read as the console shows it, its address kept masked as given", () => {
  assert.deepEqual(readUser(ADA), { user: "user-1", email: "a***@example.com", emailVerified: true, status: "active" });
  assert.deepEqual(readUser({ ...ADA, status: "disabled" })?.status, "disabled");
  assert.equal(readUser({ ...ADA, status: "locked" }), null, "a status the console does not know");
  assert.equal(readUser({ ...ADA, email_verified: "yes" }), null);
  assert.equal(readUser({ ...ADA, user: "" }), null);
});

test("a page is read whole or not at all, with its cursor only when there is a next page", () => {
  assert.deepEqual(readUsersPage({ users: [ADA], next: "user-1" })?.next, "user-1");
  assert.deepEqual(readUsersPage({ users: [ADA], next: null })?.next, null);
  assert.equal(readUsersPage({ users: [ADA] })?.next, null, "an absent cursor is no next page");
  assert.equal(readUsersPage({ users: [ADA, { user: "user-2" }], next: null }), null, "one account of another shape");
  assert.equal(readUsersPage({ users: "none", next: null }), null);
  assert.equal(readUsersPage({ users: [ADA], next: 3 }), null);
});

test("a refusal says what is left to do", () => {
  assert.deepEqual(readRefusal(401, { code: "session_required" }, null), { kind: "signed_out" });
  assert.deepEqual(readRefusal(403, { code: "role_required" }, null), { kind: "role" });
  assert.deepEqual(readRefusal(404, { code: "user_not_found" }, null), { kind: "not_found" });
  assert.deepEqual(readRefusal(429, { code: "throttled" }, "7"), { kind: "throttled", seconds: 7 });
  assert.deepEqual(readRefusal(429, null, null), { kind: "throttled", seconds: null });
  assert.deepEqual(readRefusal(409, { code: "changed_meanwhile", message: "read it again" }, null), {
    kind: "refused",
    code: "changed_meanwhile",
  });
  assert.deepEqual(readRefusal(0, null, null), { kind: "failed" });
  assert.deepEqual(readRefusal(500, { code: "internal" }, null), { kind: "failed" });
});
