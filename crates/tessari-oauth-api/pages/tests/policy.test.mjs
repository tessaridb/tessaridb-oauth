// The sign-in policy view's registration decisions, without a browser: the policy as the server answers it, the
// domains an operator typed, what a change does, and the rule a refused domain list broke.
import assert from "node:assert/strict";
import { test } from "node:test";

import { domainsFrom, domainsRefusal, readRegistration, registrationConsequence } from "../src/policy-read.ts";

test("the registration policy is read only in the shape the server answers", () => {
  const open = { open: true, domains: ["example.com"], revision: 3 };
  assert.deepEqual(readRegistration(open), open);
  assert.deepEqual(readRegistration({ open: false, domains: [], revision: 0 }), {
    open: false,
    domains: [],
    revision: 0,
  });
  assert.equal(readRegistration({ open: "yes", domains: [], revision: 1 }), null, "open not a flag");
  assert.equal(readRegistration({ open: true, domains: [7], revision: 1 }), null, "a domain not a string");
  assert.equal(readRegistration({ open: true, domains: [], revision: -1 }), null, "a negative revision");
  assert.equal(readRegistration({ open: true, domains: [], revision: 1.5 }), null, "a fractional revision");
  assert.equal(readRegistration({ open: true, domains: [] }), null, "no revision");
  assert.equal(readRegistration(null), null);
});

test("the domains are read one per line, blank lines dropped and repeats kept for the server to refuse", () => {
  assert.deepEqual(domainsFrom("example.com\n  acme.io  \n\n"), ["example.com", "acme.io"]);
  assert.deepEqual(domainsFrom("a.example\r\nb.example"), ["a.example", "b.example"]);
  assert.deepEqual(domainsFrom("x.example\nx.example"), ["x.example", "x.example"]);
  assert.deepEqual(domainsFrom("   \n"), []);
});

test("a change says what it does to who can open an account, and nothing when it changes nothing", () => {
  const closed = { open: false, domains: [], revision: 2 };
  assert.equal(registrationConsequence(closed, { open: false, domains: [] }), null);
  const kept = { open: true, domains: ["example.com", "acme.io"], revision: 4 };
  assert.equal(
    registrationConsequence(kept, { open: true, domains: ["Acme.io", "example.com"] }),
    null,
    "the same domains in another order or case",
  );
  const anyone = registrationConsequence(closed, { open: true, domains: [] });
  assert.match(anyone ?? "", /any email address/);
  const some = registrationConsequence(closed, { open: true, domains: ["example.com", "acme.io"] });
  assert.match(some ?? "", /example\.com, acme\.io/);
  assert.doesNotMatch(some ?? "", /any email address/);
  assert.match(registrationConsequence(kept, { open: false, domains: ["example.com"] }) ?? "", /Nobody/);
  assert.match(
    registrationConsequence(closed, { open: false, domains: ["example.com"] }) ?? "",
    /stays closed/,
    "a closed company changing only its domains",
  );
});

test("a refused domain list says the rule it broke, and any other answer says nothing here", () => {
  const rule = "at most 20 domains";
  assert.equal(domainsRefusal(400, { code: "domains_rejected", message: rule }), `The domains were refused: ${rule}.`);
  assert.equal(domainsRefusal(400, { code: "reason_required", message: rule }), null, "another refusal");
  assert.equal(domainsRefusal(409, { code: "domains_rejected", message: rule }), null, "another status");
  assert.equal(domainsRefusal(400, { code: "domains_rejected" }), null, "no rule");
});
