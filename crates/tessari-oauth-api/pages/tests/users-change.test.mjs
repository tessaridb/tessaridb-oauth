// The user changes' decisions, without a browser: what each change answered, and what a refused change tells the
// operator. Every answer is read as unknown and narrowed; a code is kept only from the one answer allowed to carry it.
import assert from "node:assert/strict";
import { test } from "node:test";

import { changeRefusalText } from "../src/console-copy.ts";
import { keyring, readDisabled, readIssued, readOpened, readRevealed, reasonOf } from "../src/users-change.ts";

test("an opened account is read with its address masked as given", () => {
  assert.deepEqual(readOpened({ user: "user-8", email: "n***@example.com", status: "active" }), {
    user: "user-8",
    email: "n***@example.com",
  });
  assert.equal(readOpened({ user: "user-8", status: "active" }), null);
});

test("a disable says what ended with the account and when issued access tokens stop", () => {
  assert.deepEqual(
    readDisabled({ user: "user-3", status: "disabled", sessions: 2, families: 1, access_tokens_end_by: 1761120300 }),
    { sessions: 2, families: 1, accessTokensEndBy: 1761120300 },
  );
  const wrong = { user: "user-3", status: "disabled", sessions: "2", families: 1, access_tokens_end_by: 1 };
  assert.equal(readDisabled(wrong), null);
});

test("a revealed address is read whole", () => {
  assert.deepEqual(readRevealed({ user: "user-3", email: "carol@example.com" }), { email: "carol@example.com" });
  assert.equal(readRevealed({ user: "user-3" }), null);
});

test("an enrolment code is kept only when the answer says it is the one showing", () => {
  assert.deepEqual(readIssued({ user: "user-3", code: "abc-def", shown_once: true, valid_secs: 259200 }), {
    code: "abc-def",
    validHours: 72,
  });
  assert.equal(readIssued({ user: "user-3", code: null, shown_once: false, valid_secs: 259200 }), null, "a repeat");
  assert.equal(readIssued({ user: "user-3", code: "abc", shown_once: false, valid_secs: 259200 }), null);
});

test("a reason is 1 to 500 characters after trimming", () => {
  assert.equal(reasonOf("  ticket 4411  "), "ticket 4411");
  assert.equal(reasonOf("   "), null);
  assert.equal(reasonOf("x".repeat(500)), "x".repeat(500));
  assert.equal(reasonOf("x".repeat(501)), null);
  assert.equal(reasonOf("é".repeat(500)), "é".repeat(500), "characters, not bytes");
});

test("each refused change says what happened and what to do next", () => {
  for (const code of [
    "email_taken",
    "already_enrolled",
    "account_disabled",
    "changed_meanwhile",
    "reason_required",
    "idempotency_key_reused",
    "change_in_progress",
    "cross_origin",
  ]) {
    const text = changeRefusalText(code);
    assert.notEqual(text, changeRefusalText("something-else"), code);
    assert.ok(!text.includes(code), `${code} is said in words, not as its code`);
  }
});

test("a change keeps its key while it is sent again unchanged, and gets a new one when what it sends changes", () => {
  let made = 0;
  const keyFor = keyring(() => `key-${(made += 1)}`);
  const first = keyFor({ email: "c@example.com", reason: "new starter" });
  assert.equal(keyFor({ email: "c@example.com", reason: "new starter" }), first, "a double press is one change");
  const second = keyFor({ email: "zed@example.com", reason: "new starter" });
  assert.notEqual(second, first, "another address is another change");
  assert.notEqual(keyFor({ email: "c@example.com", reason: "new starter" }), first, "going back is a new change too");
});
