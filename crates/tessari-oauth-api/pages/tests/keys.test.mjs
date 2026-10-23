// What the console's Keys view reads and says: each signing key with the state the rotation rule gives it, the answers
// to making a successor and withdrawing a key, and the server's refusals in the operator's words.
import assert from "node:assert/strict";
import { test } from "node:test";

import { keyRefusalText } from "../src/console-copy.ts";
import { offered, route } from "../src/console-read.ts";
import { readKeys, readRotated, readWithdrawn } from "../src/keys-read.ts";

test("the keys are read as the server lists them, each with its state", () => {
  assert.deepEqual(
    readKeys({
      keys: [
        { kid: "old", algorithm: "ES256", created_at: 1800000000, state: "signing", signs_from: null },
        { kid: "new", algorithm: "ES256", created_at: 1800003000, state: "waiting", signs_from: 1800003300 },
      ],
    }),
    [
      { kid: "old", algorithm: "ES256", createdAt: 1800000000, state: "signing", signsFrom: null },
      { kid: "new", algorithm: "ES256", createdAt: 1800003000, state: "waiting", signsFrom: 1800003300 },
    ],
  );
  assert.deepEqual(readKeys({ keys: [] }), []);
});

test("a list of another shape is not read", () => {
  const key = { kid: "k", algorithm: "ES256", created_at: 1, state: "signing", signs_from: null };
  assert.equal(readKeys(null), null);
  assert.equal(readKeys({ keys: [{ ...key, state: "lost" }] }), null, "a state the console does not know");
  assert.equal(readKeys({ keys: [{ ...key, kid: "" }] }), null);
  assert.equal(readKeys({ keys: [{ ...key, created_at: -1 }] }), null);
  assert.equal(readKeys({ keys: [key, "k"] }), null);
});

test("the answers to a successor and to a withdrawal are read", () => {
  assert.deepEqual(readRotated({ kid: "new", signs_from: 1800000300 }), { kid: "new", signsFrom: 1800000300 });
  assert.equal(readRotated({ kid: "new" }), null);
  assert.deepEqual(readWithdrawn({ withdrawn: "old", replacement: null }), { withdrawn: "old", replacement: null });
  assert.deepEqual(readWithdrawn({ withdrawn: "old", replacement: "new" }), { withdrawn: "old", replacement: "new" });
  assert.equal(readWithdrawn({ withdrawn: "old" }), null);
});

test("every key refusal says what to do", () => {
  for (const code of ["successor_waiting", "key_not_found", "already_withdrawn"]) {
    const text = keyRefusalText(code);
    assert.ok(text.length > 20, code);
    assert.notEqual(text, keyRefusalText("something_else"), code);
  }
});

test("Keys is its own view, offered to keys operators only", () => {
  assert.deepEqual(route("#/keys"), { kind: "keys" });
  assert.ok(offered(["keys"]).includes("keys"));
  assert.ok(!offered(["policy", "users", "clients", "audit"]).includes("keys"));
});
