// The pages' decisions, without a browser: what a step's answer means, where a refusal leaves the user, and the
// encodings the passkey step needs.
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  apiBase,
  beginBody,
  fromBase64url,
  readCompleted,
  readDelta,
  readNext,
  readPasskeyOptions,
  readRedirect,
  refusal,
  toBase64url,
} from "../src/flow.ts";

test("the API lives under the page's tenant", () => {
  assert.equal(apiBase("/acme/login", "login"), "/acme/login/api");
  assert.equal(apiBase("/acme/consent", "consent"), "/acme/login/api");
  assert.equal(apiBase("/a/b/login", "login"), "/a/b/login/api");
  assert.equal(apiBase("/acme/consent", "login"), null, "a page served somewhere else names no API");
  assert.equal(apiBase("/login", "login"), null, "no tenant");
});

test("a step's answer names the next step and nothing else", () => {
  assert.equal(readNext({ next: "identify" }), "identify");
  assert.equal(readNext({ next: "first_factor" }), "first_factor");
  assert.equal(readNext({ next: "second_factor" }), "second_factor");
  assert.equal(readNext({ next: "complete" }), "complete");
  assert.equal(readNext({ next: "admin" }), null);
  assert.equal(readNext({}), null);
  assert.equal(readNext(null), null);
});

test("a completed sign-in continues only on this server", () => {
  const origin = "https://id.example.com";
  const here = "https://id.example.com/acme/oauth2/authorize/resume?interaction=abc";
  assert.equal(readCompleted({ next: "complete", continue: here }, origin), here);
  assert.equal(
    readCompleted({ next: "complete", continue: "https://evil.example/acme" }, origin),
    null,
    "another origin is not followed",
  );
  assert.equal(readCompleted({ next: "complete", continue: "javascript:alert(1)" }, origin), null);
  assert.equal(readCompleted({ next: "complete" }, origin), null);
  assert.equal(readCompleted({ next: "identify", continue: here }, origin), null);
});

test("a decision's answer is followed only to a web or app address", () => {
  assert.equal(
    readRedirect({ redirect: "https://app.example/cb?code=x" }),
    "https://app.example/cb?code=x",
  );
  assert.equal(readRedirect({ redirect: "http://127.0.0.1:8123/cb" }), "http://127.0.0.1:8123/cb");
  assert.equal(readRedirect({ redirect: "javascript:alert(1)" }), null);
  assert.equal(readRedirect({ redirect: "data:text/html,x" }), null);
  assert.equal(readRedirect({ redirect: "not a url" }), null);
  assert.equal(readRedirect({}), null);
});

test("the consent page is told what is asked", () => {
  assert.deepEqual(
    readDelta({ client_id: "portal", scopes: ["openid", "api:read"], resources: ["https://api.example"] }),
    { clientId: "portal", scopes: ["openid", "api:read"], resources: ["https://api.example"] },
  );
  assert.equal(readDelta({ client_id: "portal", scopes: [1], resources: [] }), null);
  assert.equal(readDelta({ scopes: [], resources: [] }), null);
});

test("each refusal leaves the user somewhere definite", () => {
  assert.deepEqual(refusal(401, { code: "credentials_rejected" }, null), { kind: "rejected" });
  assert.deepEqual(refusal(410, { code: "signin_expired" }, null), { kind: "expired" });
  assert.deepEqual(refusal(401, { code: "session_required" }, null), { kind: "expired" });
  assert.deepEqual(refusal(429, { code: "rate_limited" }, "30"), { kind: "throttled", seconds: 30 });
  assert.deepEqual(refusal(429, { code: "rate_limited" }, "soon"), { kind: "throttled", seconds: null });
  assert.deepEqual(refusal(409, { code: "step_refused" }, null), { kind: "retry" });
  assert.deepEqual(refusal(500, null, null), { kind: "retry" });
});

test("base64url round-trips every byte and carries no padding", () => {
  const all = new Uint8Array(256).map((_, index) => index);
  const text = toBase64url(all);
  assert.match(text, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(fromBase64url(text), all);
  assert.equal(toBase64url(new Uint8Array([0xfb, 0xff])), "-_8");
  assert.deepEqual(fromBase64url("-_8"), new Uint8Array([0xfb, 0xff]));
  assert.equal(fromBase64url("not*base64"), null);
});

test("passkey options are read into what the browser asks for", () => {
  const options = readPasskeyOptions({
    challenge: "AAEC",
    rp_id: "id.example.com",
    user_verification: "required",
    timeout_ms: 60000,
  });
  assert.deepEqual(options, {
    challenge: new Uint8Array([0, 1, 2]),
    rpId: "id.example.com",
    userVerification: "required",
    timeout: 60000,
  });
  assert.equal(readPasskeyOptions({ challenge: "AAEC", rp_id: "x", user_verification: "never", timeout_ms: 1 }), null);
  assert.equal(readPasskeyOptions({ challenge: "*", rp_id: "x", user_verification: "preferred", timeout_ms: 1 }), null);
  assert.equal(readPasskeyOptions({ challenge: "AAEC", rp_id: "x", user_verification: "preferred" }), null);
});

test("a sign-in begins for the authorization in the address, or for the account page", () => {
  assert.deepEqual(beginBody("?interaction=abc"), { interaction: "abc" });
  assert.deepEqual(beginBody("?return=account"), { account: true });
  assert.deepEqual(beginBody("?interaction=abc&return=account"), { interaction: "abc" }, "an authorization first");
  assert.equal(beginBody("?interaction="), null);
  assert.equal(beginBody("?return=elsewhere"), null, "no other return is followed");
  assert.equal(beginBody(""), null);
});
