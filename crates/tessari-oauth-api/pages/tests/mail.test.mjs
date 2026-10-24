// What the console's Mail view reads and sends: every kind as the server answers it, with the revision a change must
// name, the bodies of a change and a reset, and the server's own words for a rule the wording broke.
import assert from "node:assert/strict";
import { test } from "node:test";

import { mailBody, mailTitle, readMail, resetBody, ruleMessage } from "../src/mail-read.ts";
import { offered, route } from "../src/console-read.ts";

const RESET = {
  kind: "reset",
  subject: "Reset your password",
  text: "Open {link} to choose a new password.\n",
  own: false,
  revision: 0,
  placeholders: ["issuer", "link"],
  required: ["link"],
};

test("every kind is read as the server answers it", () => {
  assert.deepEqual(readMail({ mail: [RESET, { ...RESET, kind: "verify", own: true, revision: 2 }] }), [
    {
      kind: "reset",
      subject: "Reset your password",
      text: "Open {link} to choose a new password.\n",
      own: false,
      revision: 0,
      placeholders: ["issuer", "link"],
      required: ["link"],
    },
    {
      kind: "verify",
      subject: "Reset your password",
      text: "Open {link} to choose a new password.\n",
      own: true,
      revision: 2,
      placeholders: ["issuer", "link"],
      required: ["link"],
    },
  ]);
});

test("an answer of another shape is not read", () => {
  assert.equal(readMail(null), null);
  assert.equal(readMail({ mail: "reset" }), null);
  assert.equal(readMail({ mail: [{ ...RESET, revision: -1 }] }), null);
  assert.equal(readMail({ mail: [{ ...RESET, own: "no" }] }), null);
  assert.equal(readMail({ mail: [{ ...RESET, placeholders: [1] }] }), null);
  assert.equal(readMail({ mail: [{ ...RESET, subject: null }] }), null);
});

test("a change names the revision read and carries the wording and the reason", () => {
  assert.deepEqual(mailBody(2, "Subject", "Text {link}", "wording"), {
    revision: 2,
    subject: "Subject",
    text: "Text {link}",
    reason: "wording",
  });
  assert.deepEqual(resetBody(3, "back"), { revision: 3, reason: "back" });
});

test("a rule the wording broke is said in the server's words, anything else in none", () => {
  const message = "this mail must carry its {link}";
  assert.equal(ruleMessage({ code: "template_rejected", message }), message);
  assert.equal(ruleMessage({ code: "reason_required", message }), null);
  assert.equal(ruleMessage({ code: "template_rejected" }), null);
});

test("every kind has a title, and an unknown one is named as it is", () => {
  assert.equal(mailTitle("reset"), "Password reset");
  assert.equal(mailTitle("signin_changed"), "Sign-in change notice");
  assert.equal(mailTitle("enrolment"), "Enrolment link");
  assert.equal(mailTitle("registration"), "Registration: enrolment link");
  assert.equal(mailTitle("registration_existing"), "Registration: notice to the owner");
  assert.equal(mailTitle("welcome"), "welcome");
});

test("the Mail section is offered with the policy role and has its own address", () => {
  assert.ok(offered(["policy"]).includes("mail"));
  assert.ok(!offered(["audit"]).includes("mail"));
  assert.deepEqual(route("#/mail"), { kind: "mail" });
});
