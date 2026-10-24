// What the account page reads when it adds an authenticator app or a passkey, without a browser.
import assert from "node:assert/strict";
import { test } from "node:test";

import { enrolRefusal, readAppSecret, readRegistration } from "../src/enrolment-read.ts";

test("an app's secret is read with the address an app scans", () => {
  assert.deepEqual(
    readAppSecret({ secret: "JBSWY3DPEHPK3PXP", uri: "otpauth://totp/acme:ada%40example.com?secret=JBSWY3DPEHPK3PXP" }),
    { secret: "JBSWY3DPEHPK3PXP", uri: "otpauth://totp/acme:ada%40example.com?secret=JBSWY3DPEHPK3PXP" },
  );
  assert.equal(readAppSecret({ secret: "JBSWY3DPEHPK3PXP", uri: "https://evil.example" }), null, "not a key URI");
  assert.equal(readAppSecret({ secret: "", uri: "otpauth://totp/x" }), null);
  assert.equal(readAppSecret(null), null);
});

const OPTIONS = {
  challenge: "AAECAw",
  rp_id: "id.example.com",
  user: { id: "dXNlci0x", name: "ada@example.com" },
  exclude: ["BAUG"],
  algorithms: [-8, -7, -257],
  user_verification: "required",
  timeout_ms: 300000,
};

test("registration options are decoded for the browser", () => {
  const read = readRegistration(OPTIONS);
  assert.notEqual(read, null);
  assert.deepEqual([...(read?.challenge ?? [])], [0, 1, 2, 3]);
  assert.equal(read?.rpId, "id.example.com");
  assert.deepEqual([...(read?.userId ?? [])], [...new TextEncoder().encode("user-1")]);
  assert.equal(read?.userName, "ada@example.com");
  assert.deepEqual(read?.exclude.map((id) => [...id]), [[4, 5, 6]]);
  assert.deepEqual(read?.algorithms, [-8, -7, -257]);
  assert.equal(read?.timeout, 300000);
});

test("registration options of another shape are refused", () => {
  assert.equal(readRegistration({ ...OPTIONS, challenge: "" }), null, "an empty challenge");
  assert.equal(readRegistration({ ...OPTIONS, challenge: "not base64url!" }), null);
  assert.equal(readRegistration({ ...OPTIONS, user: { id: "dXNlci0x" } }), null, "a user without a name");
  assert.equal(readRegistration({ ...OPTIONS, exclude: ["BAUG", 7] }), null);
  assert.equal(
    readRegistration({ ...OPTIONS, exclude: ["BAUG", "not base64url!"] }),
    null,
    "an id that is not base64url",
  );
  assert.equal(readRegistration({ ...OPTIONS, algorithms: [] }), null, "no algorithm");
  assert.equal(readRegistration({ ...OPTIONS, algorithms: [-7.5] }), null);
  assert.equal(readRegistration({ ...OPTIONS, user_verification: "discouraged" }), null);
});

test("a refused enrolment names why", () => {
  assert.equal(enrolRefusal(409, { code: "already_enrolled" }), "already-enrolled");
  assert.equal(enrolRefusal(409, { code: "nothing_pending" }), "start-again");
  assert.equal(enrolRefusal(400, { code: "code_rejected" }), "code-rejected");
  assert.equal(enrolRefusal(409, { code: "last_sign_in_method" }), "last-method");
  assert.equal(enrolRefusal(409, { code: "not_offered" }), "not-offered");
  assert.equal(enrolRefusal(409, { code: "second_factor_required" }), "keep-one");
  assert.equal(enrolRefusal(400, { code: "invalid_request" }), "not-accepted");
  assert.equal(enrolRefusal(401, { code: "reauthentication_required" }), "reauthenticate");
  assert.equal(enrolRefusal(401, { code: "session_required" }), "signed-out");
  assert.equal(enrolRefusal(403, { code: "reauthentication_required" }), "other", "only a 401 asks for a sign-in");
  assert.equal(enrolRefusal(500, { code: "session_required" }), "other");
  assert.equal(enrolRefusal(503, null), "other");
});
