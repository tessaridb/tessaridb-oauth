// The groups view's decisions, without a browser: the pages the server answers, the addresses and cursors, and the
// group a form describes.
import assert from "node:assert/strict";
import { test } from "node:test";

import { offered, route } from "../src/console-read.ts";
import {
  groupFormOf,
  groupPath,
  groupsPath,
  membersPath,
  readGroup,
  readGroupsPage,
  readMembersPage,
} from "../src/groups-read.ts";

const staff = { group: "staff", description: "the desk", roles: ["reader"], created_at: 1800000000 };

test("groups is a section of an operator holding users, with a list and a page per group", () => {
  assert.deepEqual(offered(["users"]), ["users", "groups", "operators"]);
  assert.deepEqual(route("#/groups?after=staff"), { kind: "groups", after: "staff" });
  assert.deepEqual(route("#/groups/st%20aff?after=user-1"), { kind: "group", id: "st aff", after: "user-1" });
  assert.deepEqual(route("#/groups/staff"), { kind: "group", id: "staff", after: null });
});

test("the addresses carry the cursor and escape the group", () => {
  assert.equal(groupsPath(null), "api/groups");
  assert.equal(groupsPath("a b"), "api/groups?after=a+b");
  assert.equal(groupPath("a/b"), "api/groups/a%2Fb");
  assert.equal(membersPath("staff", null), "api/groups/staff/members");
  assert.equal(membersPath("staff", "user-1"), "api/groups/staff/members?after=user-1");
});

test("a page of groups, a group and a page of members are read whole or not at all", () => {
  assert.deepEqual(readGroupsPage({ groups: [staff], next: "staff" }), {
    groups: [{ id: "staff", description: "the desk", roles: ["reader"] }],
    next: "staff",
  });
  assert.equal(readGroupsPage({ groups: [{ ...staff, roles: "reader" }], next: null }), null);
  assert.equal(readGroupsPage({ groups: [], next: 1 }), null);
  assert.deepEqual(readGroup(staff), { id: "staff", description: "the desk", roles: ["reader"] });
  assert.equal(readGroup({ ...staff, group: "" }), null);
  assert.deepEqual(
    readMembersPage({ members: [{ user: "user-1", added_at: 1800000000, added_by: "operator-1" }], next: null }),
    { members: [{ user: "user-1", addedBy: "operator-1" }], next: null },
  );
  assert.equal(readMembersPage({ members: [{ user: "user-1" }], next: null }), null);
});

test("a group form names the field to fix, or the request it makes", () => {
  assert.deepEqual(groupFormOf({ id: " staff ", description: " the desk ", roles: "reader  writer" }), {
    body: { group: "staff", description: "the desk", roles: ["reader", "writer"] },
  });
  for (const [id, roles, wrong] of [
    ["Staff", "", "id"],
    ["", "", "id"],
    ["-staff", "", "id"],
    ["staff", "Reader", "roles"],
    ["staff", "a.b", "roles"],
  ]) {
    assert.deepEqual(groupFormOf({ id, description: "", roles }), { wrong }, `${id} ${roles}`);
  }
});
