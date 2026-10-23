// What the pages say: every refusal has words that say what happened and what to do, and a scope is described in
// the user's terms when the server knows it, shown as itself when it does not.
import assert from "node:assert/strict";
import { test } from "node:test";

import { describeScope, refusalText } from "../src/copy.ts";

test("a standard scope is described, any other shown as it is", () => {
  assert.match(describeScope("openid"), /sign/i);
  assert.match(describeScope("email"), /email/i);
  assert.equal(describeScope("profile"), "Your name: full, given and family", "what profile releases, exactly");
  assert.match(describeScope("offline_access"), /signed out|not using/i);
  assert.match(describeScope("groups"), /groups/i);
  assert.match(describeScope("groups"), /roles/i);
  assert.equal(describeScope("api:read"), "api:read");
});

test("every refusal says what happened and what to do next", () => {
  const kinds = [
    { kind: "rejected" },
    { kind: "expired" },
    { kind: "throttled", seconds: 30 },
    { kind: "throttled", seconds: null },
    { kind: "retry" },
  ];
  for (const kind of kinds) {
    const text = refusalText(kind);
    assert.ok(text.split(". ").length >= 2, `${kind.kind}: ${text}`);
    assert.doesNotMatch(text, /\b(4\d\d|5\d\d)\b/, "no status number reaches the user");
  }
  assert.match(refusalText({ kind: "throttled", seconds: 30 }), /30 seconds/);
  assert.match(refusalText({ kind: "throttled", seconds: 1 }), /1 second\b/);
});

test("a first password set says to sign in, whoever opened the account", async () => {
  const { ENROL_TEXT } = await import("../src/copy.ts");
  assert.doesNotMatch(ENROL_TEXT.set, /invited/, "an account its owner opened was invited by nobody");
  assert.match(ENROL_TEXT.set, /Sign in with it/);
});
